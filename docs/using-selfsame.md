# Selfsame

## Overview

Selfsame turns your phone into the thing that says *"yes, that's me."*

You create one **home key** on your phone. Every other place you use chat — a
browser, a laptop, an agent on a workstation — gets a copy cut from it. Other
people can then check that all of those really are you, instead of taking your
word for it. And if you lose a laptop, you take that copy away from your phone,
without needing the laptop back.

The shape is the one you already know from Signal and WhatsApp Web: the phone is
the durable thing, everything else is a linked device, and you unlink from the
phone.

**One thing to be clear about first:** your home key never leaves your phone. Not
to us — there is no "us" to send it to — and not to the devices you link. Linking
does not copy the key. It publishes a signed statement saying *this other key
belongs to the same person*, which is a very different thing and is why linking
is safe over a code you show on a screen.

> **This is not finished software.** The design it implements is still in
> security review. Do not put an identity you rely on into it yet.

## Getting started

### 1. Create your home key

Open Selfsame and choose **Create my home key**.

You will be asked for a **passcode**. You will be asked for it again every time
your home key signs something — adding a device, or removing one. That is
deliberate: it is the moment where you get to notice that something is being
signed. It never leaves your phone.

### 2. Write down your twelve words

The app then shows twelve words. **Write them on paper.**

These words *are* your identity. If your phone is lost, stolen, or drowned, the
words are the only way back; nothing else and nobody else can recover it.

- Paper, not a photo. A photo lives in a cloud backup.
- Not a password manager on the same phone — if the phone goes, both go.
- Somewhere you would still find them in a year.

On a phone the app blocks screenshots on this screen. On a desktop it cannot,
and it tells you so.

### 3. Confirm three of them

You will be asked for three of the twelve, chosen at random. Until this passes,
**Selfsame will not let you link or unlink anything.**

That is not bureaucracy. An identity you cannot recover is an identity you cannot
revoke from — so if you lost the laptop, you could not take its access away. The
lock exists so the backup is real before it matters.

### 4. Meet your fingerprint

The last screen shows a small coloured picture, and beneath it something like:

```
5F 9A C9 07 2E 11
```

Those are two views of the same thing: your **identity fingerprint**. You will
see both again every time you link a device, which is why they are introduced
here — so they are familiar later.

They do different jobs, and it is worth knowing which is which.

The **picture** is for your eyes. It is generated from the fingerprint, so it
cannot drift away from it, and it is there because people are far better at
recognising a shape than at reading twelve characters. Use it the way you use a
face: to notice, instantly, when something is not the same as last time.

The **six pairs** are the value you actually check. When a screen asks you
whether two devices agree, it is asking about these characters, and it is worth
reading them one pair at a time. The picture tells you when to look harder. The
characters are the answer.

If the picture ever changes when you expected it to stay the same, that alone is
reason enough to stop and read the fingerprint carefully.

## How to

### Link a device

**Goal:** make a browser or a CLI recognisably you.

**Before you start:** your recovery phrase confirmed (step 3 above), and the
other device in front of you.

1. On the other device, ask to link. In chat that is *This is my device*; on the
   command line it is `selfsame link`. It shows a QR code and a 41-character
   code beginning `anuna1`.
2. On your phone, tap **Link a device**. Scan the QR, or tap **Enter the code by
   hand** and type it. Typing is a normal way to do this, not a fallback — the
   code is checksummed, so a typo is caught rather than quietly becoming a
   different code.
3. Read the screen that appears. This is the only screen in Selfsame where you
   give something permission, and it is worth the ten seconds:

   - **Application** and **Purpose** — what is asking, and what for. These come
     from Selfsame's own list, not from the code you scanned, so they cannot be
     faked by whatever showed you the code.
   - **The device says it is** — in the dashed box. This is the *other device's*
     description of itself. Selfsame cannot check it, and says so. A hostile
     device can put anything here, including something that looks official.
     Ignore it and read the next thing instead.
   - **Key fingerprint** — a picture, and six pairs like `C0 7A 1E 42 9B 33`
     beneath it. **The six pairs must match what the other device is showing.**
     The picture is there to make a mismatch obvious at a glance; the characters
     are what settles it. If they do not match, stop and tap *This isn't me —
     reject*.

4. Tap **Authorise** and enter your passcode.

**What you should see:** the other device now shows your identity fingerprint —
the same picture and the same `5F 9A C9 07 2E 11` from step 4 above. Check that
too. Your phone says *Telling your contacts… publishing*, and then it is done.

**How long it should take:** under thirty seconds, four taps.

### Check who someone else is

In an encrypted channel, a member who has done this shows a tick. In a plain
channel, nobody shows a tick — including you.

That is not a bug and it is not a downgrade. In a plain channel the server
relays messages without a signature you can check, so a tick there would be
attesting the *server's* word rather than the person's. Rather than show you a
marker that means less than it appears to, the app shows nothing. **Absence of a
tick is not suspicion.**

The one exception is a **key conflict**: if someone you have talked to before
turns up with a different key, you are told, because that is an event rather than
an absence.

### Unlink a device you have lost

**Goal:** stop other people treating a device as you.

1. **Devices** → tap the device → **Unlink this device** → passcode.

**What you should see:** it appears crossed out with a broken ring. Other people
stop seeing it as you, usually within a day.

**This works whether or not the device is switched on.** You do not need it back,
and it cannot refuse.

**Be precise about what it does:** it removes the *claim that the device is you*.
It does not remove the device's access to the chat — it can still connect as an
unknown member. Getting a lost laptop out of a room is the room's job; getting it
out of your identity is this.

### Move to a new phone

1. On the new phone, choose **I already have a home key**.
2. Type your twelve words and choose a new passcode for the new phone.

Your devices reappear, by name. The names are stored in your signed identity
rather than on the old phone, which is why the new phone can still tell you what
it is about to unlink.

You do not need to re-link anything. Your identity did not change; only the phone
holding it did.

## Reference

| | |
|---|---|
| Recovery phrase | 12 words, BIP-39 English |
| Link code | 41 characters, begins `anuna1`, checksummed |
| A code is valid for | 5 minutes |
| Passcode | at least 6 characters |
| Devices per identity | no limit |
| Device name length | up to 64 characters |
| Works offline | yes, except linking and unlinking, which publish |

**What leaves your phone:** the signed statements that say which keys are yours.
Those are public by design — that is how other people check them.

**What never leaves your phone:** the home key itself, your passcode, and your
twelve words.

## Troubleshooting

**"That code isn't valid."**
The code was mistyped, has already been used, has expired, or was not for this
application. Ask the other device for a fresh one. Selfsame deliberately does
not say which of those it was: telling you would also tell anyone who was
guessing.

**"That code has expired — generate a new one."**
Codes last five minutes. Start again on the other device.

**The two fingerprints don't match.**
Stop. Tap *This isn't me — reject*. Nothing has been signed and nothing has been
published. A mismatch means the reply did not come from the device in front of
you, which is exactly the case the comparison exists to catch.

**The two pictures don't match.**
Treat it exactly as above and reject. The picture is generated from the
fingerprint, so two devices showing different pictures are showing different
fingerprints — there is no case where the pictures differ and the characters
still agree.

**The pictures look the same but the characters don't.**
Believe the characters and reject. The characters are the comparison; the
picture only tells you where to look. Two fingerprints that differ will
essentially always produce different pictures, but "essentially always" is not
"always", and it is the six pairs that Selfsame's guarantee rests on.

**No picture appeared, only the characters.**
The comparison still works — it has always been the characters that matter.
Selfsame hides the picture outright rather than drawing a partial one, so a
missing picture means it declined to draw something it could not fully verify,
not that anything about the fingerprint is in doubt.

**"1 change still publishing."**
Your phone has signed something but has not yet been able to tell the network.
You are linked; other people cannot see it yet. It retries by itself. If it
persists, check your connection and reopen the app.

**"Finish writing down your recovery phrase first."**
You have not completed the three-word confirmation. Linking stays locked until
you do — see step 3.

**I've lost my phone and my twelve words.**
Your identity is gone, and it cannot be recovered by anyone. Nobody holds a copy
— that is the property that makes it yours, and it is the same property that
makes this unrecoverable. Create a new home key and link your devices to it. The
old one stays in the world as an identity nobody can change; your contacts will
see a new key and a conflict flag, which is their signal to check with you.

**Someone else's tick disappeared.**
They may have unlinked that device, or your app could not reach the network to
re-check. The app fails closed: if it cannot confirm, it shows nothing rather
than showing something stale.
