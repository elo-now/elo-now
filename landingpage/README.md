# elo.now product website

Static English website for elo.now: private team communication, Spaces, messages,
files and live sessions. The repository includes the generated pages and their
Python generator. Product screenshots show the real interface with fictional
Studio North data.

## Preview the published files

Python 3 is sufficient; no package installation or publisher configuration is
needed to preview the existing pages. From the repository root:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory landingpage
```

Open `http://127.0.0.1:8080/`. The homepage defaults to Light; `/light/` and
`/dark/` provide direct theme links. Support and legal pages are available at
`/support/`, `/privacy/`, `/terms/`, `/delete-account/` and `/community/`.

## Edit and generate

Maintain product and legal copy in [the generator](../tools/build_landing.py),
presentation in [style.css](style.css), and publisher details in an untracked
local configuration. To create that configuration:

```sh
cp landingpage/publisher.example.json landingpage/publisher.json
```

Replace the example company, address and contact fields with confirmed publisher
details before generating a page for publication. The example contains public
elo.now store URLs and non-working demonstration contact addresses. Set the
registration field if applicable; review the store links and publisher approval
flag for the intended release. This file is configuration, not a place for
passwords, service keys or other secrets.

```sh
python3 tools/build_landing.py
python3 tools/check_release_materials.py --landing-only
```

Generation updates three homepage variants, five support/legal pages, discovery
files and the application's offline legal catalog at
[`apps/desktop/src/locales/legal.en.json`](../apps/desktop/src/locales/legal.en.json).
Review those changes together. Running the generator does not rebuild installed
apps or deploy the website. The supplied copy and canonical URLs describe elo.now;
another operator must also adapt the generator's branding, origin and service
descriptions to its own deployment.

`--landing-only` checks local links, anchors, canonical URLs, structured data,
sitemap, robots file and the social preview image. It reads neither
`publisher.json` nor private store materials. The full command, without that
option, also checks publisher and store-release materials when they are available
locally. These checks validate the files, not the operation of deployed services.

## Publish

Upload these files and directories together to the HTTPS domain root:

- `index.html`, `light/` and `dark/`;
- `privacy/`, `terms/`, `support/`, `delete-account/` and `community/`;
- `style.css`, `pronunciation.js`, `favicon.svg` and `LICENSE.txt`;
- `robots.txt`, `sitemap.xml`, `assets/` and `fonts/`.

The server does not need `README.md`, `publisher.example.json`, `publisher.json`
or the Python tools. Use directory-index handling for URLs such as `/privacy/`
and correct MIME types for HTML, CSS, SVG, PNG/JPEG, JavaScript, MP3 and WOFF2.
Redirect HTTP to HTTPS. Verify all six canonical pages, `/sitemap.xml`,
`/robots.txt` and `/assets/social-preview.png` after upload.

Download links point to the Apple and Google app listings and the GitHub releases
page for desktop installers. Store approval and region determine availability.
Keep legal and support pages accessible without login.

## Assets and behavior

Fonts, images and audio are served locally. The small `pronunciation.js` script
plays `assets/elo.mp3` only after a click; there is no autoplay, analytics or
third-party media request. Other page content works without JavaScript.

Manrope is distributed under the [SIL Open Font License](fonts/OFL.txt).
`LICENSE.txt` is the project's unmodified AGPL-3.0 code license; third-party
components and brand assets retain their applicable terms. The included assets
are sufficient to serve the generated site.

Each page has a title, description, canonical URL, Open Graph and Twitter
large-card metadata, and JSON-LD. Light/dark variants canonicalize to the main
homepage. The sitemap lists six canonical URLs; the social preview is 1200×630.
No ratings or reviews are invented in the structured data.
