# Starter workflow for GitHub's code scanning catalog

These files are a submission to [actions/starter-workflows](https://github.com/actions/starter-workflows).
Once accepted, **GML Code Scanner** appears under **Security → Code scanning → Add tool** in
every repository, with a **Configure** button that creates the workflow in one click (like
other third-party scanners). Because of the `Game Maker Language` category, GitHub recommends
it on repositories it detects as GML.

To submit, after the first release:

1. In `code-scanning/gml-code-scanner.yml`, replace the placeholder SHA with the full commit SHA
   of the release tag (`git rev-parse v1.0.0^{commit}`). starter-workflows requires
   third-party actions to be pinned to a SHA.
2. Fork `actions/starter-workflows` and copy the three files to the same paths:
   - `code-scanning/gml-code-scanner.yml`
   - `code-scanning/properties/gml-code-scanner.properties.json`
   - `icons/gml-code-scanner.svg`
3. Open a pull request and fill in their template.
