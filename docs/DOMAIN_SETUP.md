# Custom domain setup

The Pages site is currently served at
`https://cyzanfar.github.io/text-watermark-remover/`. The purchased Namecheap
domain still resolves to Namecheap parking, so the repository intentionally
does not contain a `web/CNAME` file yet. Adding it first would make the live
site depend on DNS that is not ready.

To switch to `llmwatermarkremover.com`:

1. First verify ownership at the account level: GitHub profile **Settings →
   Pages → Add a domain**, enter `llmwatermarkremover.com`, and copy GitHub's
   `_github-pages-challenge-cyzanfar` TXT record into Namecheap Advanced DNS.
   Wait for it to resolve, click **Verify**, and keep the TXT record permanently
   to reduce domain-takeover risk.
2. In repository **Settings → Pages**, save `llmwatermarkremover.com` as the
   custom domain before pointing DNS at GitHub. This site deploys through an
   Actions workflow, so a checked-in `CNAME` file is neither required nor used.
3. In Namecheap Advanced DNS, delete the parking A record and parking `www`
   CNAME. Do not create wildcard DNS records.
4. Add A records for host `@` to GitHub Pages addresses `185.199.108.153`,
   `185.199.109.153`, `185.199.110.153`, and `185.199.111.153`.
5. Add a CNAME record for host `www` pointing to `cyzanfar.github.io`.
6. Wait for the repository DNS check, then enable **Enforce HTTPS**.
7. In one commit, replace canonical URLs, Open Graph URLs, and sitemap URLs
   under `web/`; switch `web/package.json` and the GitHub repository homepage;
   then submit the sitemap in Google Search Console and Bing Webmaster Tools.

Verify before switching:

```bash
dig +short llmwatermarkremover.com A
dig +short www.llmwatermarkremover.com CNAME
dig _github-pages-challenge-cyzanfar.llmwatermarkremover.com TXT
curl -I https://llmwatermarkremover.com/
```

GitHub's current domain-verification and DNS guidance is authoritative:
<https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages>.
