# Testing the EagleEye agent on a Mac

Thank you for testing. The agent has been built for macOS but never run on a real Mac, so this
session checks that it installs, connects, listens to the network and scans it. It takes about
30 minutes. Nothing on the Mac is changed apart from the agent itself, and step 6 removes it.

## What you need

- A Mac with macOS 12 or later (Apple silicon or Intel) and an administrator account.
- Python 3.12 or later. Check with `python3 --version` in Terminal. If it is older, install it from
  python.org or with `brew install python@3.12` (the `python3` that comes with macOS is too old).
- Two files from the person who sent you this guide:
  - `eagleeye-agent-0.1.0.tar.gz` (the agent), saved in `~/Downloads`
  - `code.txt` (a one-time connection code), saved in your home folder (`~/code.txt`)
- The Mac on a normal home or office network (Wi-Fi is fine), with other devices around it.

## 1. Install and connect

In Terminal:

```sh
cd ~/Downloads && tar xzf eagleeye-agent-0.1.0.tar.gz
sudo bash eagleeye-agent-0.1.0/packaging/macos/install-macos.sh eagleeye-agent-0.1.0.tar.gz --code-file ~/code.txt
```

It asks for your Mac password (for `sudo`) and takes a minute or two. It ends by showing the last
lines of the agent's log.

**Note** anything red or any line with `Error` or `Traceback`.

## 2. Check that it runs and listens

```sh
sudo eagleeye service status
```

**Note** the line that starts with `passive listening on`. It should say
`with macOS BPF device (built in)`. If it says something else, or that listening could not start,
copy the whole output.

## 3. Compare the two ways of listening (2 minutes)

The agent can listen with its own built-in capture or with libpcap (the library Wireshark uses).
This runs both at the same time and compares what each one heard:

```sh
sudo eagleeye service stop
sudo eagleeye listen --compare --seconds 120
sudo eagleeye service start
```

While it runs, use another device on the same network (unlock a phone, open a web page) so there
is something to hear.

**Copy the whole output.** The important lines are `hosts`, `names`, `dhcp` and `ssdp`: the
`built_in` numbers should be the same as (or very close to) the `npcap` ones.

## 4. Check it on the dashboard

Tell the person who sent you this guide that steps 1 to 3 are done. They check on their side that:

- the Mac shows up as an online agent,
- its inventory arrived (hardware, macOS version, apps),
- the devices it heard appear,
- an active scan of your network, started from the dashboard, finishes.

Keep the Mac awake and on the same network for about 10 minutes for this.

## 5. Send back

1. Anything you noted in steps 1 to 3 (screenshots are fine).
2. The agent's log:
   ```sh
   sudo cp "/Library/Application Support/EagleEye/logs/agent.log" ~/Desktop/eagleeye-agent.log
   ```
   then send `eagleeye-agent.log` from your Desktop.
3. Your macOS version (Apple menu → About This Mac) and whether the Mac is Apple silicon or Intel.

## 6. Remove the agent

```sh
sudo bash ~/Downloads/eagleeye-agent-0.1.0/packaging/macos/install-macos.sh --uninstall --purge
```

This removes the agent, its settings and its logs. Python and anything installed with Homebrew stay.
