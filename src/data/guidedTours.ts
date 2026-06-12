export const GUIDED_TOURS = {
  q2see: {
    repoUrl: 'https://github.com/dallascrilley/q2see-demo',
    steps: [
      {
        label: 'Start with an export',
        body: 'Upload or paste a quote-to-cash CSV/JSON export; the sample shows opportunities, quotes, contracts, invoices, and renewals in one flow.',
      },
      {
        label: 'Run the backend parser',
        body: 'Analyze export posts the file to the Cloudflare backend, normalizes lifecycle columns, and flags broken handoffs server-side.',
      },
      {
        label: 'Read the break',
        body: 'The graph and inspector show the exact stuck record, severity, source fields, and why revenue is leaking before the renewal path reaches finance.',
      },
    ],
  },
  apexlint: {
    repoUrl: 'https://github.com/dallascrilley/apexlint-demo',
    steps: [
      {
        label: 'Paste ops code',
        body: 'Use Apex, Flow JSON, or n8n DSL. Samples are editable, so the lint surface behaves like a review gate, not a screenshot.',
      },
      {
        label: 'Run deterministic rules',
        body: 'Lint on server executes the same 16-rule engine on the live backend. No model call decides whether production code is safe.',
      },
      {
        label: 'Trace every finding',
        body: 'Each result cites a rule ID, line, severity, and fix direction, with public fixtures in the repo for passing and failing cases.',
      },
    ],
  },
  tracewell: {
    repoUrl: 'https://github.com/dallascrilley/tracewell-demo',
    steps: [
      {
        label: 'Bring a run trace',
        body: 'Paste or upload a recorded agent run with steps, status, token counts, latency, errors, and model parameters.',
      },
      {
        label: 'Classify failure server-side',
        body: 'Analyze your trace sends the run to the backend, which identifies the failure mode, root-cause step, and suggested repair.',
      },
      {
        label: 'Inspect the black box',
        body: 'Timeline, tool tree, prompt diff, and token readouts make the failed run reviewable without rerunning the agent.',
      },
    ],
  },
  funnelguard: {
    repoUrl: 'https://github.com/dallascrilley/funnelguard-demo',
    steps: [
      {
        label: 'Pick a workspace config',
        body: 'Choose a synthetic HubSpot/GA4/ad-account scenario with planted UTM, form-binding, lifecycle, and attribution defects.',
      },
      {
        label: 'Check on the backend',
        body: 'Check on server posts the loaded config to the Cloudflare backend and returns byte-identical rule findings.',
      },
      {
        label: 'Follow the evidence',
        body: 'Findings point to the scanned config, severity, category, and downstream business risk so the defect is not just a warning label.',
      },
    ],
  },
  forager: {
    repoUrl: 'https://github.com/dallascrilley/forager-demo',
    steps: [
      {
        label: 'Upload Slack knowledge',
        body: 'Import a Slack export JSON file or paste normalized thread data; the sample workspace stays clearly synthetic.',
      },
      {
        label: 'Harvest resolved answers',
        body: 'The backend groups messages into threads, extracts Q&A, scores confidence, and switches the UI into your uploaded workspace.',
      },
      {
        label: 'Query like an agent',
        body: 'Ask the harvested knowledge base and inspect the MCP-style response format with source thread, confidence, and answer text.',
      },
    ],
  },
  inboxward: {
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
