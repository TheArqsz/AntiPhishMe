# Privacy Policy

## AntiPhishMe Chrome extension

AntiPhishMe extension (**The extension**) may collect:
- malicious URL (**The URL**)
- The URL's IP address
- The URL's certificates

The extension may collect this data ONLY if it happens to be active phishing and that means:
- site listed at https://hole.cert.pl/domains/domains.txt
- site verified as phishing by https://urlscan.io/
- site verified as phishing by https://safebrowsing.google.com/
- site verified as phishing by our algorithm (**the algorithm**)

Proper message about the URL's status will be presented to the User via extension's pop-up message.

Collected data cannot be associated with any user. No personal data, that users may be identified by, is stored. URLs, IPs and certificates are stored anonymously.

However your browser might collect some data (for example updates to The Extension are handled by the Google Web Store website and are subject to the [Google Privacy Policy](https://policies.google.com/privacy)).

### The algorithm

The extension uses the algorithm to determine whether the URL is malicious or not.
The Algorithm consists of:
- entropy calculation
- Levenstein's distance calculation
- urlscan.io verification
- safebrowsing's verification
- who.is verification (domain age)
- crt.sh verification (cert's age)

### Remote services

The Extension connects to remote services listed below to determine URL's/domain's/IP's status:
- https://urlscan.io
- https://safebrowsing.google.com/
- https://hole.cert.pl/domains/domains.txt
- https://who.is/
- https://crt.sh/
- http://ip-api.com

Proper privacy policies from each of Remote Services applies.
