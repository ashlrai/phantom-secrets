export type CommercialOffering = {
  id: "community" | "enterprise" | "government";
  name: string;
  price: string;
  pitch: string;
  featured: boolean;
  features: readonly string[];
  cta: { label: string; href: string };
};

export const COMMERCIAL_CONTACT = "mason@ashlr.ai";

export const COMMERCIAL_OFFERINGS = [
  {
    id: "community",
    name: "Open source",
    price: "$0",
    pitch: "Use, modify, and distribute Phantom's local-first core under MIT.",
    featured: false,
    features: [
      "CLI, local vault, proxy, and MCP server",
      "No seat count or local-secret limit imposed by Phantom",
      "Community support through GitHub",
      "Self-directed deployment and validation",
    ],
    cta: {
      label: "View the repository",
      href: "https://github.com/ashlrai/phantom-secrets",
    },
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "Scoped",
    pitch: "Contract for evaluation, integration, and support around the MIT core.",
    featured: true,
    features: [
      "Written pilot scope and acceptance criteria",
      "Architecture and security-boundary review",
      "Integration with named repositories and supported clients",
      "Support commitments only as written in the agreement",
    ],
    cta: {
      label: "Scope an enterprise evaluation",
      href: `mailto:${COMMERCIAL_CONTACT}?subject=Phantom%20enterprise%20evaluation`,
    },
  },
  {
    id: "government",
    name: "Government",
    price: "Scoped",
    pitch: "Evaluate a local-first workflow against a named public-sector environment.",
    featured: false,
    features: [
      "Bounded technical evaluation with explicit exclusions",
      "Evidence packet for the reviewed source and test scope",
      "Environment-specific integration and risk review",
      "Procurement and support terms only by written agreement",
    ],
    cta: {
      label: "Discuss a government evaluation",
      href: `mailto:${COMMERCIAL_CONTACT}?subject=Phantom%20government%20evaluation`,
    },
  },
] as const satisfies readonly CommercialOffering[];

export const COMMERCIAL_NON_CLAIMS = [
  "No generally available Phantom Cloud service or hosted control plane",
  "No shipped SSO, SAML, or SCIM integration",
  "No regulatory certification, authorization, or compliance attestation",
  "No contractual SLA unless one is expressly included in a signed agreement",
  "No supported self-hosted enterprise control plane",
] as const;

export const COMMERCIAL_INTAKE = [
  "The repositories, teams, operating systems, and AI clients in scope",
  "The exact local workflow and non-production acceptance criteria",
  "Security, data-residency, procurement, and support requirements",
  "Required timeline, stakeholders, and decision owner",
] as const;
