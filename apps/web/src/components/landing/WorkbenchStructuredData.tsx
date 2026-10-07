function serializeStructuredData(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export function WorkbenchStructuredData() {
  return <>
    {/* JSON-LD: SoftwareApplication */}
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: serializeStructuredData({
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      name: "Phantom",
      url: "https://phm.dev",
      applicationCategory: "DeveloperApplication",
      applicationSubCategory: "AgenticEngineering",
      codeRepository: "https://github.com/ashlrai/ashlr-hub",
      downloadUrl: "https://verse.ashlr.ai/#start",
      description: "An engineering workbench for interactive agent sessions, autonomous fleet workflows and connected resources.",
      author: { "@type": "Organization", name: "AshlrAI, Inc.", url: "https://ashlr.ai" },
      license: "https://opensource.org/licenses/MIT",
    }) }} />
    {/* JSON-LD: SoftwareSourceCode */}
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: serializeStructuredData({
      "@context": "https://schema.org",
      "@type": "SoftwareSourceCode",
      name: "Phantom engineering workbench",
      codeRepository: "https://github.com/ashlrai/ashlr-hub",
      license: "https://opensource.org/licenses/MIT",
      targetProduct: { "@type": "SoftwareApplication", name: "Phantom", url: "https://phm.dev" },
    }) }} />
  </>;
}
