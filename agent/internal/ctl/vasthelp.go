package ctl

// VastEnrollHelp is printed by `happyminingctl vast-enroll-help`.
//
// It deliberately contains no command to copy: the install command of the
// official Vast host software is tied to the operator's Vast account and is
// obtained from the Vast console by the operator.
const VastEnrollHelp = `Installing the official Vast host software (manual, local-operator step)
=========================================================================

HappyMining OS does NOT install the Vast host software for you, and this tool
does not download, embed, store or automate the Vast install command or any
Vast account key. Enrolling a machine as a Vast host is done by a person who
is authorised to use the hosting account, on the machine itself.

Why it is manual
  - The install command is shown in the Vast console to the signed-in hosting
    account. Treat it as account-linked and short-lived: it is a credential.
  - Putting that command or an account key into an image, a package or a
    script would spread a reusable account credential to every machine.
  - Accepting Vast's host agreement is a decision for the account holder.

Procedure
  1. Run the preflight and fix every FAIL before going further:
         sudo happyminingctl preflight
     Passing preflight does not guarantee that Vast verifies the machine.
  2. On another device, sign in to the Vast console with the hosting account
     and open the host setup guide:
         https://cloud.vast.ai/host/setup/
     Read the current requirements there; they take precedence over anything
     HappyMining tools say.
  3. Follow the setup guide on this machine, typing or pasting the install
     command it shows you into a root shell yourself. Do not save the command
     in a file, a shell history you share, a ticket or a chat.
  4. When the Vast installer has finished, check that the machine shows up in
     the Vast console, then tell your HappyMining administrator. Binding the
     machine to its owner in HappyMining is done by an authorised operator on
     the server side, never by this machine.
  5. Check that the HappyMining agent still reports:
         happyminingctl status

What HappyMining tools never do
  - They never call Vast's API and never hold a Vast account key.
  - They never modify, reinstall or remove the Vast host software or Docker.
  - They never read renter containers, files or processes.

Credentials that the Vast installer itself puts on the machine belong to Vast
and are outside HappyMining's control. Anyone with root access on this machine
can read them.
`
