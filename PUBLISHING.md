# Publishing VulnLens

The extension is packaged as `vuln-lens-<version>.vsix`. Publishing to the
Visual Studio Marketplace needs a Microsoft account and a Personal Access Token
(PAT); it cannot be done from this repository alone.

## One-time setup

1. Sign in to [Azure DevOps](https://dev.azure.com) with a Microsoft account.
   Create a free organization if you do not have one.
2. Open **User settings** (top right) → **Personal access tokens** → **New Token**.
   - **Organization:** *All accessible organizations*
   - **Scopes:** *Custom defined* → **Marketplace** → **Manage**
   - Copy the token; it is shown once.
3. Open the [Marketplace management page](https://marketplace.visualstudio.com/manage)
   and click **Create publisher**.
   - **ID:** `battleangel` (must match `publisher` in `package.json`)
   - **Name:** `VulnLens` (or anything readable)
4. Log in from the terminal:

   ```bash
   npx vsce login battleangel
   ```

   Paste the PAT when prompted.

## Publish a version

1. Bump `version` in `package.json` (for example `0.2.0` → `0.2.1`).
2. Update `CHANGELOG.md`.
3. Build and publish:

   ```bash
   npm run check
   npx vsce publish
   ```

   `vsce` runs `vscode:prepublish` (`npm run compile`), packages the extension,
   and uploads it. To upload an existing VSIX instead:

   ```bash
   npx vsce publish --packagePath vuln-lens-0.2.0.vsix
   ```

4. Check the listing:
   <https://marketplace.visualstudio.com/items?itemName=battleangel.vuln-lens>

## Notes

- The publisher ID is permanent. If `battleangel` is taken, change `publisher`
  in `package.json` to the ID you created before publishing.
- `README.md` becomes the listing page. Relative links are rewritten to the
  GitHub repository, which is why `repository` is set in `package.json`.
- `assets/icon.png` (256×256) is the listing icon.
- A VSIX can also be attached to a GitHub release for people who do not use the
  Marketplace.
