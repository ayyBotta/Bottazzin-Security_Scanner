"""Catalogo dei domini ufficiali dei marchi piu' imitati e scomposizione dei domini."""

from __future__ import annotations

from ..domains import MULTI_PART_SUFFIXES, DomainParts, split_domain  # noqa: F401 (riesportati)

# Marchio -> domini ufficiali. Sono i bersagli piu' frequenti del phishing,
# internazionale e italiano. Si puo' estendere liberamente.
BRANDS: dict[str, list[str]] = {
    # Big tech e servizi online
    "Google": ["google.com", "google.it", "gmail.com", "googleapis.com", "googleusercontent.com"],
    "YouTube": ["youtube.com"],
    "Microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "bing.com"],
    "Apple": ["apple.com", "icloud.com"],
    "Amazon": ["amazon.com", "amazon.it", "amazon.de", "amazon.fr", "amazon.es", "amazon.co.uk"],
    "Meta / Facebook": ["facebook.com", "fb.com", "messenger.com"],
    "Instagram": ["instagram.com"],
    "WhatsApp": ["whatsapp.com"],
    "X / Twitter": ["x.com", "twitter.com"],
    "LinkedIn": ["linkedin.com"],
    "TikTok": ["tiktok.com"],
    "Telegram": ["telegram.org"],
    "Discord": ["discord.com"],
    "Zoom": ["zoom.us"],
    "Netflix": ["netflix.com"],
    "Spotify": ["spotify.com"],
    "Steam": ["steampowered.com", "steamcommunity.com"],
    "GitHub": ["github.com", "github.io", "githubusercontent.com", "githubassets.com"],
    "Dropbox": ["dropbox.com"],
    "Adobe": ["adobe.com"],
    "Yahoo": ["yahoo.com"],
    "Cloudflare": ["cloudflare.com"],
    "Wikipedia": ["wikipedia.org"],
    "OpenAI": ["openai.com", "chatgpt.com"],
    # Pagamenti, e-commerce, crypto
    "PayPal": ["paypal.com", "paypal.it", "paypal.me"],
    "eBay": ["ebay.com", "ebay.it"],
    "Satispay": ["satispay.com"],
    "Binance": ["binance.com"],
    "Coinbase": ["coinbase.com"],
    "Zalando": ["zalando.it", "zalando.com"],
    "Subito": ["subito.it"],
    "Booking": ["booking.com"],
    "Airbnb": ["airbnb.com", "airbnb.it"],
    # Spedizioni e trasporti
    "DHL": ["dhl.com", "dhl.it"],
    "UPS": ["ups.com"],
    "FedEx": ["fedex.com"],
    "BRT": ["brt.it"],
    "Trenitalia": ["trenitalia.com"],
    "Italo": ["italotreno.it", "italotreno.com"],
    "Ryanair": ["ryanair.com"],
    # Banche italiane
    "Poste Italiane": ["poste.it", "posteitaliane.it"],
    "Intesa Sanpaolo": ["intesasanpaolo.com"],
    "UniCredit": ["unicredit.it", "unicredit.eu"],
    "BPER": ["bper.it"],
    "Banco BPM": ["bancobpm.it"],
    "BNL": ["bnl.it"],
    "Fineco": ["finecobank.com"],
    "Banca Mediolanum": ["bancamediolanum.it"],
    "Credem": ["credem.it"],
    "Monte dei Paschi": ["mps.it"],
    "Credit Agricole": ["credit-agricole.it"],
    # Pubblica amministrazione e utility
    "INPS": ["inps.it"],
    "Agenzia delle Entrate": ["agenziaentrate.gov.it"],
    "SPID / AgID": ["spid.gov.it", "agid.gov.it"],
    "Aruba": ["aruba.it"],
    "TIM": ["tim.it"],
    "Vodafone": ["vodafone.it", "vodafone.com"],
    "WindTre": ["windtre.it"],
    "Iliad": ["iliad.it"],
    "Enel": ["enel.it", "enel.com"],
}

class BrandCatalog:
    """Indici sul catalogo: dominio ufficiale -> marchio, nome -> (marchio, dominio)."""

    def __init__(self, brands: dict[str, list[str]] | None = None):
        self.brands = brands or BRANDS
        self.official: dict[str, str] = {}
        self.names: dict[str, tuple[str, str]] = {}
        for brand, domains in self.brands.items():
            for domain in domains:
                self.official[domain] = brand
                self.names.setdefault(split_domain(domain).name, (brand, domain))

    def brand_of(self, registrable: str) -> str | None:
        return self.official.get(registrable)

    def official_domains(self, brand: str) -> list[str]:
        return self.brands.get(brand, [])

    def __len__(self) -> int:
        return len(self.official)
