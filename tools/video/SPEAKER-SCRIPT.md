# Speaker Script - demo video (62 s, 8 scenes)

Layman-language lines, one per scene, matched to the video timeline.
Total speaking time about 70 seconds. Keep the pace calm and point at
the screen as each scene appears.

---

## Before the video (10 s)

> Idea in one sentence: every phonecall between two computers is like a
> conversation at a post office counter. We record who talks, how fast,
> how long, and when they pause - then stamp 69 standard measurements on
> every conversation so a security system can spot bad behaviour in a crowd.

---

## Scene by scene

### 1. Title card - 0:00-0:05
> This video shows our CIC-IDS2017 flow feature extractor. It is a
> network conversation recorder that matches the official academic lab
> standard used in intrusion-detection research.

### 2. What it produces - 0:05-0:11
> If two computers exchange packets - like typing messages back and
> forth - our tool groups those packets into one 'conversation' and
> calculates 69 numbers about it: how many packets went each way, how
> fast, how regularly, how much data, when the talking paused.

### 3. Pipeline - 0:11-0:20
> The journey of one packet. It gets read from a saved file or live from
> your network cable - we attach it to its conversation using the same
> rules as the official CICFlowMeter software, count the numbers, and
> write one clean row of 69 values. Two long-pause rules: if a
> conversation is quiet for 120 seconds we call it finished, and pauses
> longer than 5 seconds are marked as 'idle time'.

### 4. Live demo - 0:20-0:32
> This is not stock footage - this terminal shows the tool running on a
> real laptop right now. Give it a single command and a saved network
> file, and it prints the finished conversation rows in under a second.
> The same command works for JSON, and for live capture we swap the file
> path for an interface name.

### 5. One flow, one row - 0:32-0:42
> Every conversation becomes exactly one line: 69 numbers, nothing more.
> No headers, no labels - deliberately, so researchers can feed the rows
> straight into machine learning. And we never write NaN or Infinity:
> if a statistic cannot be calculated, we write 0.0 instead. That keeps
> training data clean.

### 6. Validation - 0:42-0:50
> We proved it works. 40 automated tests all pass, comparing feature
> numbers against hand-computed answers and against a network recording
> we made ourselves, where we already know every answer in advance.

### 7. Live capture - 0:50-0:56
> On this machine we found the network cables it can listen to. Point the
> tool at one and it prints the same 69-value rows live, while traffic
> is actually flowing.

### 8. Closing credits - 0:56-1:02
> Thank you. The whole project - code, tests, and this video - is public
> on GitHub, built with Python, Scapy, and Npcap.

---

## 30-second version (if the judges ask for a quick cut)

> Deliver the title line, then scene 3, scene 4, scene 6, and stop at the
> credits. Time checks:
> 0:00 title -> 0:05 pipeline -> 0:14 true demo -> 0:22 validation ->
> 0:28 thank you.

---

## Judge questions you can pre-empt

- Why 69 features? 'So the numbers match the public CIC-IDS-2017 dataset
  exactly, and any model trained on that data works on ours.'
- Why no NaN/Inf? 'Machine learning hates missing values - we write 0.0
  instead, so pipelines never crash.'
- Live vs saved files? 'Same engine. --pcap for replay, --interface for
  real-time; identical rows either way.'
- How do you know it is correct? '40 tests, plus a network recording we
  made where every answer was known before the tool ran.'