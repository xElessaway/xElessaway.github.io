---
title: "I Found a Stranger’s Phone. I Had No Way In. So, I Built One."
description: "A real story about mobile forensics, FRP bypass, chipset research, and passive OSINT, all in service of getting a phone back to its owner."
publishedAt: 2026-06-06
archiveSection: reports
tags:
  - "mobileforensics"
  - "dfir"
  - "osint"
  - "samsung"
  - "frp"
  - "androidforensics"
  - "cybersecurity"
cover: "https://cdn-images-1.medium.com/max/600/1*UcHIymc3Zy-J1bmGb1n5jQ.png"
featured: true
draft: false
---

<p><em>A real story about mobile forensics, FRP bypass, chipset research, and passive OSINT, all in service of getting a phone back to its owner.</em></p>

<blockquote>
<em>⚠️ <strong>Disclaimer</strong>: Everything described in this article was performed on a found device with the sole intent of identifying and contacting its owner. All techniques are shared for <strong>educational purposes only</strong>. Do not attempt these methods on devices you don’t own or have explicit authorization to examine.</em>
</blockquote>

<p>It started with a phone on the floor of a mall.</p>
<p>No one around it. No one is looking for it. Just a Samsung Galaxy A14 sitting there, screen locked, completely unresponsive to anything except a PIN prompt.</p>

<div class="evidence-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin: 1.5rem 0;">
  <figure><img loading="lazy" referrerpolicy="no-referrer" alt="Locked Samsung Galaxy A14" src="https://cdn-images-1.medium.com/max/600/1*UcHIymc3Zy-J1bmGb1n5jQ.png" /><figcaption>Exhibit A: Found Samsung Galaxy A14 (Screen Locked)</figcaption></figure>
  <figure><img loading="lazy" referrerpolicy="no-referrer" alt="Samsung Galaxy A14 Rear Chassis" src="https://cdn-images-1.medium.com/max/600/1*n_ccUQQrdXJ1ulXQ9q-CKw.jpeg" /><figcaption>Exhibit B: Device Rear Chassis</figcaption></figure>
</div>

<p>My first instinct wasn’t to hand it in somewhere and forget about it. My instinct was: <em>I work in DFIR. I should be able to figure out who this belongs to.</em> So I picked it up and started thinking.</p>

<h2>The First Wall: USB Debugging Is Off</h2>

<p>The obvious move for anyone with a forensics background is to plug the phone in and see what ADB gives you. But that requires <strong>USB Debugging</strong> to be enabled in Developer Options, and on a device that’s PIN-locked, you can’t access Developer Options. The phone shows up as a generic storage device, and every forensic tool you try either fails silently or throws a “device not authorized” error.</p>

<p>No ADB. No shell access. No MTP beyond the basics. The phone was a brick from a software perspective.</p>

<h2>Plan A: Factory Reset + Data Carving</h2>

<p>When live access is blocked, you fall back on the next thing: wipe it and recover what you can.</p>

<p>The logic was simple. If I factory reset the phone, it boots into setup mode. At that point, I can enable USB Debugging during the initial setup flow, connect the device, and use data carving tools to recover deleted artifacts, photos, contacts, call logs, and anything that survived the wipe in unallocated space. Even a single contact name or photo with a face is enough to start an OSINT trace.</p>

<p>So I held Volume Down + Power, entered Recovery Mode, and wiped the device.</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="Android Recovery Mode" src="https://cdn-images-1.medium.com/max/800/1*25-9IIFaX9eQbN_cP7aZ4g.jpeg" /><figcaption>Exhibit C: Entering Android Recovery Mode to Wipe Device</figcaption></figure>

<p>The phone rebooted. The setup wizard appeared. I pressed Start.</p>
<p>And then I hit the second wall.</p>

<h2>The FRP Problem Nobody Warns You About</h2>

<p><strong>FRP (Factory Reset Protection)</strong> is a Google security feature that activates the moment you factory reset a device linked to a Google account. After the reset, the phone refuses to complete setup unless you sign in with the exact Google account previously associated with the device.</p>

<p>From Google’s perspective, the logic is sound: if someone steals your phone and wipes it, they still can’t use it without your credentials. It’s a good feature. It just destroyed my plan.</p>

<p>I connected the phone to SamFw Tool 5.4 to check the state:</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="SamFw Tool FRP Lock Verification" src="https://cdn-images-1.medium.com/max/800/1*djr-P29F82lxApQfujV7Ig.png" /><figcaption>Exhibit D: SamFw Tool 5.4 Query: FRP status: LOCK</figcaption></figure>

<p><code>FRP status: LOCK</code>. The phone was going nowhere.</p>

<h2>The Research Phase: What Chipset Is This Thing Running?</h2>

<p>This is where things slowed down and got methodical.</p>

<p>I spent time going through the usual routes: SamFw’s built-in FRP removal options, various Odin3-based firmware-flashing approaches, and community methods circulating for the A14 series. Some required paid server credits. Some were Android version-specific and didn’t apply here. Some simply didn’t work.</p>

<p>After hitting dead ends, I shifted my approach. Instead of looking for a generic “Samsung FRP bypass”, I started asking a more specific question: <strong>what chipset is actually in this phone?</strong></p>

<p>Why does that matter? FRP bypass methods, especially through forensic tools, are <strong>chipset-specific</strong>. The same model number can ship with completely different silicon depending on the region and production batch, and the tooling that works for one variant will do nothing for the other.</p>

<p>A quick search confirmed the split:</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="Samsung Galaxy A14 Chipset Variants Research" src="https://cdn-images-1.medium.com/max/800/1*Vi_3yROX3ybZ8rUOx21bqw.png" /><figcaption>Exhibit E: Researching SM-A145F Chipset Allocations (MediaTek vs Exynos)</figcaption></figure>

<blockquote>
<strong><em>Samsung Galaxy SM-A145F ships with either MediaTek MT6769 Helio G80 or Samsung Exynos 850, depending on the regional market.</em></strong>
</blockquote>

<p>To cross-verify, I pulled the full device specs from Phonedb:</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="Phonedb Hardware Specification Sheet" src="https://cdn-images-1.medium.com/max/800/1*VBYb4OG2G3JAAJeBEDpzRw.png" /><figcaption>Exhibit F: Phonedb Hardware Specification Confirmation</figcaption></figure>

<p>Same model. Same variant. Samsung Exynos 850: <strong>confirmed</strong>.</p>
<p>Now the real question was: <strong>what can we actually do with an Exynos on a locked device?</strong></p>

<h2>Confirming the Chipset via Download Mode</h2>

<p>To check which variant I had, I entered <strong>Download Mode</strong>: Power off the device, then hold Volume Down + Volume Up + plug in USB simultaneously.</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="Samsung Download Mode Screen" src="https://cdn-images-1.medium.com/max/800/1*OgmdY4KKQCfWhuS7keGDNg.png" /><figcaption>Exhibit G: Bootloader Telemetry in Samsung Download Mode</figcaption></figure>

<p>The bootloader screen showed the device binary, OEM lock status, and hardware identifiers. The chipset was confirmed to be the <strong>Samsung Exynos 850</strong>.</p>
<p>That one confirmation changed everything.</p>

<h2>MOBILedit Forensic Ultra: The Exynos Decrypt Path</h2>

<p>MOBILedit Forensic Ultra has a specific extraction method for Exynos devices called <strong>“Boot recovery and decrypt”</strong>. The process works by booting a custom recovery on the device to obtain root-level access, then decrypting the device storage at the partition level to bypass FRP, since FRP operates below the Android OS layer.</p>

<p>The workflow inside MOBILedit:</p>

<p><strong>Step 1: Choose model:</strong><br>SM-A145F wasn’t in the list.</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="MOBILedit Step 1 Model Selection" src="https://cdn-images-1.medium.com/max/800/1*gT75sIrVkIX4USkO3Bn2_w.png" /><figcaption>Exhibit H: MOBILedit Step 1 - Model Not Directly Listed</figcaption></figure>

<p>MOBILedit didn’t have this specific variant. So instead of searching by model, I pivoted; if the tool knows the chipset, that’s enough. The chipset is what drives the extraction method anyway, not the marketing name on the box.</p>

<p><strong>Step 2: Choose a chipset:</strong><br>Samsung Exynos 850, confirmed.</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="MOBILedit Step 2 Chipset Selection" src="https://cdn-images-1.medium.com/max/800/1*A323op09ph8ISjqDK7pyyw.png" /><figcaption>Exhibit I: MOBILedit Step 2 - Direct Selection of Exynos 850</figcaption></figure>

<p>This is the critical selection; a wrong chipset here means the recovery boot will fail or brick the process entirely.</p>

<p><strong>Step 3: Choose action:</strong><br>“Boot recovery and decrypt”, the description says it all: custom recovery, root access, partition-level decryption.</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="MOBILedit Step 3 Action Selection" src="https://cdn-images-1.medium.com/max/800/1*F_YykL5xc73bv-9RYr-v7g.png" /><figcaption>Exhibit J: Selecting 'Boot Recovery and Decrypt'</figcaption></figure>

<p>Devices with secure startup may need password brute force; this one didn’t.</p>
<p>I hit Next and watched the output:</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="MOBILedit Partition Decryption Progress" src="https://cdn-images-1.medium.com/max/800/1*w4InW-bARbzvFvq2Nodcdg.png" /><figcaption>Exhibit K: MOBILedit Boot Recovery & Decryption Execution</figcaption></figure>

<p><strong>The phone rebooted to the Welcome screen.</strong></p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="Device Rebooted to Welcome Screen" src="https://cdn-images-1.medium.com/max/800/1*s68bXMVn_q75NSmRASDEAg.png" /><figcaption>Exhibit L: Device Rebooted into Accessible Diagnostic State</figcaption></figure>

<p>The decryption worked, but FRP wasn’t gone yet. What MOBILedit actually did was get the device into a state where USB Debugging became accessible. That was the real unlock. From here, I could actually talk to the phone.</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="USB Debugging Authorization Screen" src="https://cdn-images-1.medium.com/max/800/1*W_lbzaaMiTfIoIMCM_QyPQ.jpeg" /><figcaption>Exhibit M: USB Debugging RSA Authorization Prompt Triggered</figcaption></figure>

<p>With ADB (Android Debug Bridge) connection established, I moved to Android Utility PRO to handle the FRP removal itself.</p>

<h2>Android Utility PRO: Validating the State</h2>

<p>The log showed exactly what happened:</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="Android Utility PRO Log" src="https://cdn-images-1.medium.com/max/800/1*iGQSK0EzylTXDyDlvkKBag.png" /><figcaption>Exhibit N: Android Utility PRO Log - FRP Removed Successfully</figcaption></figure>

<p>FRP removed. Device rebooted to recovery. Factory reset performed. Done.</p>
<p>Now the phone was fully open, no FRP, no lock. But also no data. The factory reset had wiped everything the original owner had. I needed to find them a different way.</p>

<h2>Pivoting to OSINT: The SIM Card as an Identity Anchor</h2>

<p>With the phone now in a clean setup state, I walked through the initial Android setup without signing in to any Google account, reached the home screen, and enabled USB Debugging in Developer Options.</p>

<p>ADB was now live. But a freshly wiped device has nothing to carve. The only artifact remaining was the <strong>SIM card</strong>.</p>

<p>I inserted it and waited for the chance that someone would call. Nobody called.</p>

<p>So I took the number and ran it through two passive lookup tools:</p>
<ul>
  <li><strong>GetContact</strong>, a crowd-sourced contact database built from what other users have saved in their phonebooks</li>
  <li><strong>Truecaller</strong>, same concept at a global scale, with a significantly larger dataset</li>
</ul>

<p>Both returned the same name. Let’s call him <strong>Sayed</strong>.</p>

<h2>The WhatsApp Confirmation</h2>

<p>A name from a passive OSINT lookup is a lead, not a confirmation. Numbers get saved under the wrong names. Databases go stale. I needed verification before reaching out.</p>

<p>Here’s where the SIM card becomes more than just a phone number.</p>

<p><strong>WhatsApp ties accounts to SIM numbers.</strong> If I install WhatsApp on the device using the inserted SIM, it authenticates against WhatsApp’s servers using that number and loads the account history, contacts, chat inbox, everything. The data lives on the server, not on the device. A factory reset doesn’t touch it.</p>

<p>Using the SamFw Tool’s App Manager to push the APK via ADB:</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="SamFw Tool APK Deployment via ADB" src="https://cdn-images-1.medium.com/max/800/1*c7c4zxWDAFQSC_1XIyTGMg.png" /><figcaption>Exhibit O: SamFw Tool App Manager - Deploying WhatsApp APK</figcaption></figure>

<p>WhatsApp was registered, the account was loaded, and the inbox was opened.</p>
<p>The first contact name that appeared: <strong>Sayed</strong>.</p>

<figure><img loading="lazy" referrerpolicy="no-referrer" alt="WhatsApp Account Cross-Confirmation" src="https://cdn-images-1.medium.com/max/800/1*Vm2HAFZvhiIe3T-MR5xJ2A.png" /><figcaption>Exhibit P: WhatsApp Server-Side Contact Verification</figcaption></figure>

<p>The passive OSINT lookup matched what WhatsApp’s own server-side data knew about that number’s social network. Cross-confirmed. Same person.</p>
<p>I sent a message explaining the situation. Got a reply within minutes. Arranged the handoff. Phone returned.</p>

<h2>What This Case Actually Demonstrates</h2>

<h3>Mobile Forensics</h3>
<ul>
  <li>Understanding when ADB access is and isn’t possible based on device state</li>
  <li>Factory reset + data carving as a standard fallback when live access is blocked</li>
  <li>FRP is a critical post-reset blocker that changes the entire extraction path</li>
  <li>Download Mode as a hardware information source independent of the Android OS</li>
</ul>

<h3>Chipset Research</h3>
<ul>
  <li>Identical model numbers can carry completely different silicon depending on the region/batch.</li>
  <li>Forensic tooling, especially partition-level decryption, is chipset-specific, not model-specific</li>
  <li>Verifying hardware before selecting a toolchain is not optional; it’s a required step.</li>
</ul>

<h3>DFIR Tooling</h3>
<ul>
  <li><strong>SamFw Tool</strong>: FRP status verification, ADB-based APK delivery</li>
  <li><strong>MOBILedit Forensic Ultra</strong>: Exynos-specific boot recovery and partition decryption</li>
  <li><strong>Android Utility PRO</strong>: Post-bypass device state validation</li>
</ul>

<h3>Passive OSINT</h3>
<ul>
  <li>SIM number as a persistent identity anchor that survives a device wipe</li>
  <li>GetContact and Truecaller for crowd-sourced number-to-identity attribution</li>
  <li>WhatsApp account recovery as a server-side identity cross-reference</li>
  <li>Understanding that app-layer identity data lives on the SIM + server, not on device storage</li>
</ul>

<h2>The Key Lesson</h2>

<p>The single decision that unlocked this entire case was <strong>confirming the chipset before committing to a toolchain</strong>.</p>

<p>Every bypass method, every forensic tool, every community guide you find online makes implicit assumptions about the hardware it’s targeting. If you don’t verify those assumptions first, you can spend hours on techniques that were never going to work on your device, not because you did them wrong, but because they were never written for your hardware.</p>

<p>The model number is not enough. Check the chipset. Then pick your tools.</p>
