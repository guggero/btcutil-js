// Resolves the btcutil-js module for the example pages, so the deployed
// (GitHub Pages) copy works without the gitignored dist/ directory:
//
//   1. ../../dist/index.js — the local build. Always present in a repo
//      checkout (Node demo, local dev server) and always matches the
//      example code.
//   2. jsDelivr (npm mirror), pinned to the version in the repo's
//      package.json — "the module's current version". The bundled module
//      has no bare imports and resolves btcutil.wasm relative to its own
//      URL, so the wasm loads from the CDN too (correct content-type and
//      CORS verified).
//   3. jsDelivr @latest, if package.json isn't served either.
//
// After loading, the required namespaces are verified: a CDN version that
// predates the neutrino module fails loudly instead of half-working.

const cdnUrl = (version) =>
  `https://cdn.jsdelivr.net/npm/btcutil-js@${version}/dist/index.js`;

export async function loadBtcutil() {
  let mod = null;
  let source = 'local build (dist/)';

  try {
    mod = await import('../../dist/index.js');
  } catch {
    // No local build (e.g. the deployed static page): find the repo's
    // current version and pull that exact release from the npm CDN.
    let version = 'latest';
    try {
      const resp = await fetch(
        new URL('../../package.json', import.meta.url),
      );
      if (resp.ok) {
        version = (await resp.json()).version ?? 'latest';
      }
    } catch {
      // package.json not served — fall through to @latest.
    }

    try {
      mod = await import(cdnUrl(version));
      source = `npm via jsDelivr (@${version})`;
    } catch {
      mod = await import(cdnUrl('latest'));
      source = 'npm via jsDelivr (@latest)';
    }
  }

  for (const ns of ['neutrino', 'descriptors', 'txscript']) {
    if (!mod[ns]) {
      throw new Error(`the loaded btcutil-js (${source}) is missing the ` +
        `'${ns}' module — the published npm version is older than this ` +
        'example; build dist/ locally or publish a new release');
    }
  }

  return { ...mod, source };
}
