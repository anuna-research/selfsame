//! Transport-neutral live relay sessions for the Selfsame pairing shells.
//!
//! A shell supplies one binary WebSocket message at a time and performs only
//! the returned [`LiveEffect::Send`] operations. Relay binding, mailbox
//! membership, sequence/acknowledgement handling, endpoint transitions,
//! consent ordering, and terminal closure stay in this module.

use cbcl_pairing::{
    endpoint::{EndpointEffect, TerminalReason},
    profile::{
        CredentialGrant, CredentialIntentClaims, CREDENTIAL_ACTION, CREDENTIAL_APPLICATION,
        CREDENTIAL_PAYLOAD,
    },
    wire::{
        decode_channel_frame, decode_server_message, encode_channel_frame, encode_client_message,
        encode_invitation, ApplicationPayload, ChannelFrame, ClientMessage, CloseReason,
        Invitation, Locator, PairingIntent, ServerMessage, Side,
    },
};
use zeroize::Zeroize;

pub use cbcl_pairing::{profile::DisplayIntent, wire::Decision};

use crate::{
    recognise_transfer_claims, CredentialTransfer, IntegrationError, SelfsameEndpoint,
    SelfsameEndpointBootstrap, SelfsameEndpointEffect, SelfsameVerificationContext,
};

/// Fresh values owned by one allocator attempt.
pub struct AllocatorEntropy {
    /// Password-related invitation secret.
    pub invitation_secret: [u8; 16],
    /// Allocator CPace scalar input.
    pub cpace_scalar: [u8; 32],
    /// Allocator ceremony signing seed.
    pub signing_seed: [u8; 32],
    /// Fresh application-intent nonce.
    pub intent_nonce: [u8; 32],
}

impl Drop for AllocatorEntropy {
    fn drop(&mut self) {
        self.invitation_secret.zeroize();
        self.cpace_scalar.zeroize();
        self.signing_seed.zeroize();
        self.intent_nonce.zeroize();
    }
}

/// Observable terminal result of a live relay session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveOutcome {
    /// The claimant accepted one credential through the Selfsame verifier.
    Accepted,
    /// The allocator delivered one payload; claimant acceptance remains local.
    Delivered,
    /// The claimant explicitly declined before payload release.
    Declined,
    /// The local endpoint cancelled the attempt.
    Cancelled,
    /// The relay closed before a successful application result.
    Closed,
    /// The claimant refused a protocol message or transferred credential.
    Refused,
}

/// Shell effects released by a live endpoint session.
#[derive(Debug)]
pub enum LiveEffect {
    /// Send one canonical `ClientMessage` as a binary WebSocket message.
    Send(Vec<u8>),
    /// Publish the complete out-of-band invitation.
    Invitation(Vec<u8>),
    /// Display the completely recognised, channel-authenticated intent.
    DisplayIntent(DisplayIntent),
    /// The allocator has sent its authenticated intent and awaits consent.
    AwaitingDecision,
    /// The allocator released exactly one payload after approval.
    PayloadSent,
    /// The claimant accepted the payload through the Selfsame verifier.
    Accepted,
    /// The relay and endpoint reached a terminal outcome.
    Terminal(LiveOutcome),
}

enum AllocatorPhase {
    AwaitWelcome,
    AwaitAllocation,
    Bootstrap(Box<Option<SelfsameEndpointBootstrap>>),
    Endpoint(Box<SelfsameEndpoint>),
    Terminal,
}

/// One allocator endpoint driven by canonical relay messages.
pub struct AllocatorRelaySession {
    relay_origin: String,
    transfer: CredentialTransfer,
    expected_grant_body: Vec<u8>,
    entropy: Option<AllocatorEntropy>,
    intent_nonce: [u8; 32],
    phase: AllocatorPhase,
    next_seq: u8,
    next_peer_seq: u8,
    intent_sent: bool,
    payload_sent: bool,
}

impl AllocatorRelaySession {
    /// Prepare an allocator without allocating a production invitation.
    ///
    /// The caller chooses the relay process. This adapter sends the ordinary
    /// relay `Allocate` command only when its explicit live connection receives
    /// `Welcome`; it never consults the production-allocation policy.
    pub fn new(
        relay_origin: String,
        transfer: CredentialTransfer,
        verification: &SelfsameVerificationContext,
        entropy: AllocatorEntropy,
    ) -> Result<Self, IntegrationError> {
        if transfer.bundle.len() > crate::MAX_CREDENTIAL_PAYLOAD_OCTETS {
            return Err(IntegrationError::Profile);
        }
        recognise_transfer_claims(&transfer, verification)?;
        let expected_grant_body = CredentialGrant {
            application_id: transfer.application_id.clone(),
            origin: transfer.origin.clone(),
            scope: transfer.scope.clone(),
            recipient: transfer.recipient.clone(),
            credential: transfer.bundle.clone(),
        }
        .encode()
        .map_err(|_| IntegrationError::Profile)?;
        let intent_nonce = entropy.intent_nonce;
        Ok(Self {
            relay_origin,
            transfer,
            expected_grant_body,
            entropy: Some(entropy),
            intent_nonce,
            phase: AllocatorPhase::AwaitWelcome,
            next_seq: 0,
            next_peer_seq: 0,
            intent_sent: false,
            payload_sent: false,
        })
    }

    /// First canonical relay message for a newly opened connection.
    pub fn start(&self) -> Result<Vec<u8>, IntegrationError> {
        encode_client_message(&ClientMessage::Bind).map_err(|_| IntegrationError::Recognition)
    }

    /// Apply one complete canonical relay response.
    pub fn receive(&mut self, input: &[u8]) -> Result<Vec<LiveEffect>, IntegrationError> {
        let message = decode_server_message(input).map_err(|_| IntegrationError::Recognition)?;
        match message {
            ServerMessage::Welcome if matches!(self.phase, AllocatorPhase::AwaitWelcome) => {
                self.phase = AllocatorPhase::AwaitAllocation;
                Ok(vec![send(ClientMessage::Allocate {
                    locator_mode: 0,
                    ttl_seconds: Some(600),
                })?])
            }
            ServerMessage::Allocated {
                mailbox_id,
                mut membership_token,
                ..
            } if matches!(self.phase, AllocatorPhase::AwaitAllocation) => {
                membership_token.zeroize();
                self.allocated(mailbox_id)
            }
            ServerMessage::Frame { peer_seq, body } => self.receive_frame(peer_seq, &body),
            ServerMessage::Acknowledged { .. } | ServerMessage::Pong => Ok(Vec::new()),
            ServerMessage::Closed(reason) => self.relay_closed(reason),
            ServerMessage::Error(_) => Err(IntegrationError::Pairing),
            _ => Err(IntegrationError::State),
        }
    }

    /// Cancel locally and close the selected mailbox.
    pub fn cancel(&mut self) -> Result<Vec<LiveEffect>, IntegrationError> {
        let phase = std::mem::replace(&mut self.phase, AllocatorPhase::Terminal);
        let mut effects = match phase {
            AllocatorPhase::Endpoint(mut endpoint) => endpoint
                .cancel()?
                .into_iter()
                .map(|effect| match effect {
                    EndpointEffect::SendFrame(frame) => self.put_frame(&frame),
                    EndpointEffect::CloseMailbox => send(ClientMessage::Close),
                    EndpointEffect::DisplayIntent(_) | EndpointEffect::DeliverGrant(_) => {
                        Err(IntegrationError::State)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?,
            AllocatorPhase::Terminal => return Ok(Vec::new()),
            _ => vec![send(ClientMessage::Close)?],
        };
        effects.push(LiveEffect::Terminal(LiveOutcome::Cancelled));
        Ok(effects)
    }

    fn allocated(&mut self, mailbox_id: [u8; 32]) -> Result<Vec<LiveEffect>, IntegrationError> {
        let entropy = self.entropy.take().ok_or(IntegrationError::State)?;
        let invitation = Invitation {
            application: CREDENTIAL_APPLICATION.into(),
            relay_origin: self.relay_origin.clone(),
            locator: Locator::Direct(mailbox_id),
            secret: entropy.invitation_secret.to_vec(),
            expected_allocator_key: None,
            expected_claimant_key: None,
        };
        let carrier = encode_invitation(&invitation).map_err(|_| IntegrationError::Recognition)?;
        let bootstrap = SelfsameEndpointBootstrap::start(
            Side::Allocator,
            &carrier,
            mailbox_id,
            entropy.cpace_scalar,
            entropy.signing_seed,
        )?;
        let cpace = bootstrap.local_cpace_frame_bytes()?;
        self.phase = AllocatorPhase::Bootstrap(Box::new(Some(bootstrap)));
        Ok(vec![
            LiveEffect::Invitation(carrier),
            self.put_bytes(cpace)?,
        ])
    }

    fn receive_frame(
        &mut self,
        peer_seq: u8,
        body: &[u8],
    ) -> Result<Vec<LiveEffect>, IntegrationError> {
        if peer_seq != self.next_peer_seq {
            return Err(IntegrationError::Pairing);
        }
        self.next_peer_seq = self
            .next_peer_seq
            .checked_add(1)
            .ok_or(IntegrationError::Pairing)?;
        let mut effects = vec![send(ClientMessage::Ack { peer_seq })?];
        let frame = decode_channel_frame(body).map_err(|_| IntegrationError::Recognition)?;
        match &mut self.phase {
            AllocatorPhase::Bootstrap(slot) => {
                let bootstrap = slot.take().ok_or(IntegrationError::State)?;
                let mut endpoint = bootstrap.finish(&frame)?;
                let finished = endpoint
                    .local_finished_frame()?
                    .ok_or(IntegrationError::Pairing)?;
                self.phase = AllocatorPhase::Endpoint(Box::new(endpoint));
                effects.push(self.put_frame(&finished)?);
            }
            AllocatorPhase::Endpoint(_) => {
                effects.extend(self.receive_endpoint_frame(&frame)?);
            }
            _ => return Err(IntegrationError::State),
        }
        Ok(effects)
    }

    fn receive_endpoint_frame(
        &mut self,
        frame: &ChannelFrame,
    ) -> Result<Vec<LiveEffect>, IntegrationError> {
        let mut endpoint = match std::mem::replace(&mut self.phase, AllocatorPhase::Terminal) {
            AllocatorPhase::Endpoint(endpoint) => endpoint,
            phase => {
                self.phase = phase;
                return Err(IntegrationError::State);
            }
        };
        let raw = endpoint.receive_frame(frame, None)?;
        let mut effects = Vec::new();
        for effect in raw {
            match effect {
                SelfsameEndpointEffect::SendFrame(frame) => effects.push(self.put_frame(&frame)?),
                SelfsameEndpointEffect::CloseMailbox => {
                    effects.push(send(ClientMessage::Close)?);
                }
                SelfsameEndpointEffect::DisplayIntent(_) | SelfsameEndpointEffect::Accepted(_) => {
                    return Err(IntegrationError::State)
                }
            }
        }
        if endpoint.session_ready() && !self.intent_sent {
            let claims = CredentialIntentClaims {
                application_id: self.transfer.application_id.clone(),
                origin: self.transfer.origin.clone(),
                scope: self.transfer.scope.clone(),
                recipient: self.transfer.recipient.clone(),
            };
            let (allocator_claim, claimant_claim) =
                claims.encode().map_err(|_| IntegrationError::Profile)?;
            let intent = PairingIntent {
                application: CREDENTIAL_APPLICATION.into(),
                action: CREDENTIAL_ACTION.into(),
                allocator_claim,
                claimant_claim,
                authority_summary: "Transfer one Selfsame device grant".into(),
                intent_nonce: self.intent_nonce,
            };
            effects.push(self.put_frame(&endpoint.send_intent(&intent)?)?);
            effects.push(LiveEffect::AwaitingDecision);
            self.intent_sent = true;
        } else if self.intent_sent
            && !self.payload_sent
            && endpoint.terminal_reason() != Some(TerminalReason::Declined)
            && endpoint.intent_digest().is_some()
        {
            let payload = ApplicationPayload {
                intent_digest: endpoint.intent_digest().ok_or(IntegrationError::State)?,
                payload_type: CREDENTIAL_PAYLOAD.into(),
                body: self.expected_grant_body.clone(),
            };
            effects.push(self.put_frame(&endpoint.send_payload(&payload)?)?);
            effects.push(LiveEffect::PayloadSent);
            self.payload_sent = true;
        }
        self.phase = AllocatorPhase::Endpoint(endpoint);
        Ok(effects)
    }

    fn put_frame(&mut self, frame: &ChannelFrame) -> Result<LiveEffect, IntegrationError> {
        let body = encode_channel_frame(frame).map_err(|_| IntegrationError::Recognition)?;
        self.put_bytes(body)
    }

    fn put_bytes(&mut self, body: Vec<u8>) -> Result<LiveEffect, IntegrationError> {
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(IntegrationError::Pairing)?;
        send(ClientMessage::Put { seq, body })
    }

    fn relay_closed(&mut self, reason: CloseReason) -> Result<Vec<LiveEffect>, IntegrationError> {
        let phase = std::mem::replace(&mut self.phase, AllocatorPhase::Terminal);
        let outcome = match phase {
            AllocatorPhase::Endpoint(mut endpoint) => {
                if endpoint.terminal_reason().is_none() {
                    let _ = endpoint.relay_closed(reason)?;
                }
                if self.payload_sent {
                    LiveOutcome::Delivered
                } else if endpoint.terminal_reason() == Some(TerminalReason::Declined) {
                    LiveOutcome::Declined
                } else {
                    LiveOutcome::Closed
                }
            }
            AllocatorPhase::Terminal => return Ok(Vec::new()),
            _ => LiveOutcome::Closed,
        };
        Ok(vec![LiveEffect::Terminal(outcome)])
    }
}

enum ClaimantPhase {
    AwaitWelcome(Option<SelfsameEndpointBootstrap>),
    AwaitClaim(Option<SelfsameEndpointBootstrap>),
    Bootstrap(Option<SelfsameEndpointBootstrap>),
    Endpoint(Box<SelfsameEndpoint>),
    Terminal,
}

/// One claimant endpoint driven by canonical relay messages.
pub struct ClaimantRelaySession {
    locator: Locator,
    verification: SelfsameVerificationContext,
    phase: ClaimantPhase,
    next_seq: u8,
    next_peer_seq: u8,
    accepted: bool,
    declined: bool,
}

impl ClaimantRelaySession {
    /// Begin a claimant from one completely recognised invitation.
    pub fn new(
        invitation: &[u8],
        cpace_scalar: [u8; 32],
        signing_seed: [u8; 32],
        verification: SelfsameVerificationContext,
    ) -> Result<Self, IntegrationError> {
        let recognised = crate::decode_selfsame_invitation(invitation)?;
        let locator = recognised.locator;
        let bootstrap =
            SelfsameEndpointBootstrap::join_claimant(invitation, cpace_scalar, signing_seed)?;
        Ok(Self {
            locator,
            verification,
            phase: ClaimantPhase::AwaitWelcome(Some(bootstrap)),
            next_seq: 0,
            next_peer_seq: 0,
            accepted: false,
            declined: false,
        })
    }

    /// First canonical relay message for a newly opened connection.
    pub fn start(&self) -> Result<Vec<u8>, IntegrationError> {
        encode_client_message(&ClientMessage::Bind).map_err(|_| IntegrationError::Recognition)
    }

    /// Apply one complete canonical relay response.
    pub fn receive(&mut self, input: &[u8]) -> Result<Vec<LiveEffect>, IntegrationError> {
        let message = decode_server_message(input).map_err(|_| IntegrationError::Recognition)?;
        match message {
            ServerMessage::Welcome => {
                let bootstrap = match std::mem::replace(&mut self.phase, ClaimantPhase::Terminal) {
                    ClaimantPhase::AwaitWelcome(value) => value,
                    phase => {
                        self.phase = phase;
                        return Err(IntegrationError::State);
                    }
                };
                self.phase = ClaimantPhase::AwaitClaim(bootstrap);
                Ok(vec![send(ClientMessage::Claim(self.locator.clone()))?])
            }
            ServerMessage::Claimed {
                mailbox_id,
                mut membership_token,
                ..
            } => {
                if self.locator != Locator::Direct(mailbox_id) {
                    membership_token.zeroize();
                    return Err(IntegrationError::Pairing);
                }
                let bootstrap = match std::mem::replace(&mut self.phase, ClaimantPhase::Terminal) {
                    ClaimantPhase::AwaitClaim(value) => value.ok_or(IntegrationError::State)?,
                    phase => {
                        self.phase = phase;
                        return Err(IntegrationError::State);
                    }
                };
                let cpace = bootstrap.local_cpace_frame_bytes()?;
                self.phase = ClaimantPhase::Bootstrap(Some(bootstrap));
                // Claim attaches the second member but does not replay bodies
                // queued before that attachment. An immediate authenticated
                // Open retrieves allocator sequence zero without reconnecting.
                let open = encode_client_message(&ClientMessage::Open {
                    mailbox_id,
                    membership_token,
                })
                .map_err(|_| IntegrationError::Recognition)?;
                membership_token.zeroize();
                Ok(vec![LiveEffect::Send(open), self.put_bytes(cpace)?])
            }
            ServerMessage::Frame { peer_seq, body } => self.receive_frame(peer_seq, &body),
            ServerMessage::Acknowledged { .. } | ServerMessage::Pong => Ok(Vec::new()),
            ServerMessage::Closed(reason) => self.relay_closed(reason),
            ServerMessage::Error(_) => Err(IntegrationError::Pairing),
            _ => Err(IntegrationError::State),
        }
    }

    /// Commit one explicit local decision after [`LiveEffect::DisplayIntent`].
    pub fn decide(&mut self, decision: Decision) -> Result<Vec<LiveEffect>, IntegrationError> {
        let endpoint = match &mut self.phase {
            ClaimantPhase::Endpoint(endpoint) => endpoint,
            _ => return Err(IntegrationError::State),
        };
        let raw = endpoint.decide(decision)?;
        self.declined = decision == Decision::Decline;
        self.raw_effects(raw)
    }

    /// Cancel locally and close the selected mailbox.
    pub fn cancel(&mut self) -> Result<Vec<LiveEffect>, IntegrationError> {
        let phase = std::mem::replace(&mut self.phase, ClaimantPhase::Terminal);
        let mut effects = match phase {
            ClaimantPhase::Endpoint(mut endpoint) => self.raw_effects(endpoint.cancel()?)?,
            ClaimantPhase::Terminal => return Ok(Vec::new()),
            _ => vec![send(ClientMessage::Close)?],
        };
        effects.push(LiveEffect::Terminal(LiveOutcome::Cancelled));
        Ok(effects)
    }

    fn receive_frame(
        &mut self,
        peer_seq: u8,
        body: &[u8],
    ) -> Result<Vec<LiveEffect>, IntegrationError> {
        if peer_seq != self.next_peer_seq {
            return Err(IntegrationError::Pairing);
        }
        self.next_peer_seq = self
            .next_peer_seq
            .checked_add(1)
            .ok_or(IntegrationError::Pairing)?;
        let mut effects = vec![send(ClientMessage::Ack { peer_seq })?];
        let frame = decode_channel_frame(body).map_err(|_| IntegrationError::Recognition)?;
        match &mut self.phase {
            ClaimantPhase::Bootstrap(slot) => {
                let bootstrap = slot.take().ok_or(IntegrationError::State)?;
                let mut endpoint = bootstrap.finish(&frame)?;
                let finished = endpoint
                    .local_finished_frame()?
                    .ok_or(IntegrationError::Pairing)?;
                self.phase = ClaimantPhase::Endpoint(Box::new(endpoint));
                effects.push(self.put_frame(&finished)?);
            }
            ClaimantPhase::Endpoint(_) => {
                let mut endpoint = match std::mem::replace(&mut self.phase, ClaimantPhase::Terminal)
                {
                    ClaimantPhase::Endpoint(endpoint) => endpoint,
                    _ => unreachable!(),
                };
                let raw = match endpoint.receive_frame(&frame, Some(&self.verification)) {
                    Ok(raw) => raw,
                    Err(_) => {
                        // This one-use invitation cannot safely continue after
                        // a protocol or verifier refusal. Keep the private
                        // reason local, close the relay mailbox, and erase the
                        // endpoint as this branch returns.
                        effects.push(send(ClientMessage::Close)?);
                        effects.push(LiveEffect::Terminal(LiveOutcome::Refused));
                        self.phase = ClaimantPhase::Terminal;
                        return Ok(effects);
                    }
                };
                for effect in raw {
                    match effect {
                        SelfsameEndpointEffect::SendFrame(frame) => {
                            effects.push(self.put_frame(&frame)?);
                        }
                        SelfsameEndpointEffect::DisplayIntent(intent) => {
                            effects.push(LiveEffect::DisplayIntent(intent));
                        }
                        SelfsameEndpointEffect::Accepted(value) => {
                            drop(value);
                            self.accepted = true;
                            effects.push(LiveEffect::Accepted);
                            effects.push(send(ClientMessage::Close)?);
                        }
                        SelfsameEndpointEffect::CloseMailbox => {
                            effects.push(send(ClientMessage::Close)?);
                        }
                    }
                }
                self.phase = ClaimantPhase::Endpoint(endpoint);
            }
            _ => return Err(IntegrationError::State),
        }
        Ok(effects)
    }

    fn raw_effects(
        &mut self,
        raw: Vec<EndpointEffect>,
    ) -> Result<Vec<LiveEffect>, IntegrationError> {
        raw.into_iter()
            .map(|effect| match effect {
                EndpointEffect::SendFrame(frame) => self.put_frame(&frame),
                EndpointEffect::CloseMailbox => send(ClientMessage::Close),
                EndpointEffect::DisplayIntent(_) | EndpointEffect::DeliverGrant(_) => {
                    Err(IntegrationError::State)
                }
            })
            .collect()
    }

    fn put_frame(&mut self, frame: &ChannelFrame) -> Result<LiveEffect, IntegrationError> {
        let body = encode_channel_frame(frame).map_err(|_| IntegrationError::Recognition)?;
        self.put_bytes(body)
    }

    fn put_bytes(&mut self, body: Vec<u8>) -> Result<LiveEffect, IntegrationError> {
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(IntegrationError::Pairing)?;
        send(ClientMessage::Put { seq, body })
    }

    fn relay_closed(&mut self, reason: CloseReason) -> Result<Vec<LiveEffect>, IntegrationError> {
        let phase = std::mem::replace(&mut self.phase, ClaimantPhase::Terminal);
        match phase {
            ClaimantPhase::Endpoint(mut endpoint) => {
                if endpoint.terminal_reason().is_none() {
                    let _ = endpoint.relay_closed(reason)?;
                }
            }
            ClaimantPhase::Terminal => return Ok(Vec::new()),
            _ => {}
        }
        let outcome = if self.accepted {
            LiveOutcome::Accepted
        } else if self.declined {
            LiveOutcome::Declined
        } else {
            LiveOutcome::Closed
        };
        Ok(vec![LiveEffect::Terminal(outcome)])
    }
}

fn send(message: ClientMessage) -> Result<LiveEffect, IntegrationError> {
    encode_client_message(&message)
        .map(LiveEffect::Send)
        .map_err(|_| IntegrationError::Recognition)
}
