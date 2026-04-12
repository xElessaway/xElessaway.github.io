export const siteMeta = {
  title: "Ahmed Elessaway (xElessaway)",
  description:
    "Threat Intelligence and DFIR-focused cybersecurity engineer building blue-team labs, OSINT workflows, and practical investigation content.",
  tagline:
    "DFIR, threat intelligence, OSINT, and blue-team training systems.",
  siteUrl: "https://xelessaway.github.io",
  socials: [
    {
      label: "GitHub",
      href: "https://github.com/xelessaway"
    },
    {
      label: "LinkedIn",
      href: "https://www.linkedin.com/in/ahmedelessaway/"
    },
    {
      label: "X",
      href: "https://x.com/ahmed_elessaway"
    },
    {
      label: "Medium",
      href: "https://xelessaway.medium.com/"
    }
  ],
  nav: [
    { label: "Home", href: "/" },
    { label: "Blog", href: "/blog/" },
    { label: "Threat Intelligence", href: "/threat-intelligence/" },
    { label: "CTF", href: "/ctf/" },
    { label: "About", href: "/about/" }
  ]
};

export const toolGroups = [
  {
    label: "DFIR",
    tools: ["Autopsy", "Wireshark", "Windows Artifacts", "Linux Artifacts"]
  },
  {
    label: "Threat Intel",
    tools: ["OpenCTI", "VirusTotal", "MITRE ATT&CK", "IOC Triage"]
  },
  {
    label: "Detection",
    tools: ["Splunk", "ELK", "Microsoft Sentinel", "Sigma"]
  },
  {
    label: "OSINT",
    tools: ["GHunt", "GeoINT", "IMINT", "Social Discovery"]
  },
  {
    label: "Scripting / Automation",
    tools: ["PowerShell", "Python", "Bash", "Git"]
  }
] as const;
