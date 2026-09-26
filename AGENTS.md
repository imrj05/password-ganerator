# Repository Guidelines

## Project Structure & Module Organization
- `src/` hosts popup logic; `PopupApp.jsx` orchestrates views, `components/` holds reusable UI, and utilities live in `lib/` and `storageUtils.js` for state or Chrome APIs.
- Password engines sit in `src/securePasswordGenerator.js` and `src/memorablePasswordGenerator.js`; in-page messaging lives in the root `contentScript.js` and the MV3 service worker is `background.js`.
- Tests mirror features in `src/__tests__/`, while build artifacts compile to `dist/`, static assets live under `icons/`, and helper scripts reside in `scripts/`.

## Build, Test, and Development Commands
- `npm run dev` boots Vite with hot reload for rapid popup iteration.
- `npm run build` compiles a production bundle into `dist/`.
- `npm run build:dist` chains the build with `scripts/copy-assets.js` to stage icons and the manifest before Chrome load.
- `npm run preview` serves the built bundle for manual smoke checks.
- `npm run test` (or `npx vitest --run`) executes the Vitest JSDOM suite headlessly.

## Coding Style & Naming Conventions
- Use 2-space indentation, single quotes, and omit semicolons; rely on Vite errors to catch formatting slips early.
- Name React components in PascalCase (e.g., `PasswordControls.jsx`), hooks as `useThing`, and shared utilities in lower camelCase.
- Compose Tailwind classes inside JSX via helpers from `components/ui/` to keep styling consistent.

## Testing Guidelines
- Add specs beside the feature under test using `featureName.test.js` naming.
- Cover generator boundaries (length, separators, symbol sets) and persistence flows; mock Chrome APIs with utilities in `lib/` when needed.
- Run `npx vitest --run` before PRs to guarantee deterministic CI parity.

## Commit & Pull Request Guidelines
- Follow Conventional Commit prefixes (`feat:`, `fix:`, `chore:`) and keep subjects under 72 characters.
- PRs should describe intent, link issues, and include screenshots or GIFs for UI changes.
- Document new permissions, note manual verification (e.g., Chrome load plus all password modes), and justify any missing tests.

## Security & Extension Packaging Tips
- Keep cryptography routed through `securePasswordGenerator` or `memorablePasswordGenerator`; never fall back to `Math.random()`.
- Load the packaged extension via `npm run build:dist` then Chrome's "Load unpacked" pointing to `dist/`, verifying each generator mode end-to-end.
