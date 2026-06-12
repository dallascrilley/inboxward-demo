export const GUIDED_TOURS = {
  inboxward: {
    repoLabel: 'Inboxward',
    repoUrl: 'https://github.com/dallascrilley/inboxward-demo',
    steps: [
      {
        label: 'Inspect a real domain',
        body: 'Enter any public domain to run live SPF, DKIM, and DMARC lookup through the Cloudflare backend.',
      },
      {
        label: 'Compare fleet risk',
        body: 'The live lookup sits beside a labeled synthetic sending fleet with blacklist and inbox-placement scenarios.',
      },
      {
        label: 'Prioritize remediation',
        body: 'The cockpit turns DNS/auth results into a score, priority queue, domain detail, and action order for deliverability cleanup.',
      },
    ],
  },
} as const;
