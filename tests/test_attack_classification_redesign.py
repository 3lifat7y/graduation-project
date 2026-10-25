import os
import re
import unittest

class TestAttackClassificationRedesign(unittest.TestCase):
    """
    Validation suite for the SCOUT Attack Classification & Signatures redesign.
    Verifies vector icons, removal of all images, card hierarchy, metrics preservation,
    theme compatibility, and auto-patrol marquee behavior.
    """

    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.template_path = os.path.join(cls.base_dir, "templates", "ddos.html")
        cls.css_path = os.path.join(cls.base_dir, "static", "style.css")
        cls.js_path = os.path.join(cls.base_dir, "static", "main.js")

        with open(cls.template_path, "r", encoding="utf-8") as f:
            cls.template_content = f.read()

        with open(cls.css_path, "r", encoding="utf-8") as f:
            cls.css_content = f.read()

        with open(cls.js_path, "r", encoding="utf-8") as f:
            cls.js_content = f.read()

        # Extract the Threat Intelligence Section (Section 5)
        section_match = re.search(
            r'<section[^>]*class="[^"]*threat-intel-section[^"]*"[^>]*>(.*?)</section>',
            cls.template_content,
            re.DOTALL
        )
        cls.section_html = section_match.group(1) if section_match else ""

    def test_threat_intel_section_exists(self):
        self.assertTrue(bool(self.section_html), "Threat intelligence section not found in ddos.html")

    def test_no_attack_images_or_stock_photos(self):
        """Rule 1: Remove all photographic images, stock illustrations, and broken image elements from cards."""
        # Find all cards inside threat intelligence
        cards = re.findall(r'<div class="card attack-card-item"[^>]*>(.*?)</div>\s*(?=<!--|<div class="card attack-card-item"|</div>\s*</div>)', self.section_html, re.DOTALL)
        self.assertGreaterEqual(len(cards), 14, f"Expected 14 attack cards, found {len(cards)}")

        for idx, card in enumerate(cards, 1):
            self.assertNotIn("<img", card, f"Card {idx} contains an <img> tag!")
            self.assertNotIn(".jpg", card, f"Card {idx} references .jpg!")
            self.assertNotIn(".png", card, f"Card {idx} references .png!")
            self.assertNotIn(".jpeg", card, f"Card {idx} references .jpeg!")
            self.assertNotIn("background-image", card, f"Card {idx} uses background-image!")

    def test_all_14_cards_have_vector_icons(self):
        """Rule 2 & 3: Assign clean, meaningful vector icons in a compact emblem to each attack category."""
        expected_icons = [
            ("DDoS", "fa-server"),
            ("Hulk", "fa-bolt-lightning"),
            ("GoldenEye", "fa-link-slash"),
            ("Slowloris", "fa-hourglass-half"),
            ("Slowhttptest", "fa-sliders"),
            ("SQL", "fa-database"),
            ("XSS", "fa-code"),
            ("Brute", "fa-key"),
            ("SSH", "fa-terminal"),
            ("FTP", "fa-folder-tree"),
            ("Heartbleed", "fa-heart-pulse"),
            ("PortScan", "fa-crosshairs"),
            ("Bot", "fa-robot"),
            ("Infiltration", "fa-user-secret"),
        ]

        for attack_name, icon_class in expected_icons:
            pattern = rf'<h3>[^<]*{attack_name}[^<]*</h3>'
            self.assertTrue(
                re.search(pattern, self.section_html, re.IGNORECASE),
                f"Missing attack card for: {attack_name}"
            )
            self.assertIn(icon_class, self.section_html, f"Missing vector icon {icon_class} for {attack_name}")

    def test_card_layout_four_tier_hierarchy(self):
        """Rule 4: Verify the 4-tier consistent hierarchy on every attack card."""
        cards = re.findall(r'<div class="card attack-card-item"[^>]*>(.*?)</div>\s*(?=<!--|<div class="card attack-card-item"|</div>\s*</div>)', self.section_html, re.DOTALL)
        for idx, card in enumerate(cards, 1):
            # Tier 1: attack-card-header with emblem and badges
            self.assertIn('class="attack-card-header"', card, f"Card {idx} missing attack-card-header")
            self.assertIn('class="attack-icon-emblem"', card, f"Card {idx} missing attack-icon-emblem")
            self.assertIn('class="attack-card-badges"', card, f"Card {idx} missing attack-card-badges")
            self.assertIn('attack-type-tag', card, f"Card {idx} missing attack-type-tag")
            self.assertIn('protocol-tag', card, f"Card {idx} missing protocol-tag")

            # Tier 2: Attack name (h3)
            self.assertIn('<h3>', card, f"Card {idx} missing h3 title")

            # Tier 3: Description (p)
            self.assertIn('<p>', card, f"Card {idx} missing p description")

            # Tier 4: Footer metadata (card-footer-meta)
            self.assertIn('class="card-footer-meta"', card, f"Card {idx} missing card-footer-meta")
            self.assertIn('recall-rate', card, f"Card {idx} missing recall-rate")

    def test_preservation_of_all_attack_classes_and_metrics(self):
        """Rule 5: Preserve all 14 attack classes and baseline Class 0 with real metrics."""
        # Class 0: Benign baseline card
        self.assertIn("benign-baseline-card", self.section_html)
        self.assertIn("Class 0: Benign", self.section_html)
        self.assertIn("99.97%", self.section_html)  # Test Precision
        self.assertIn("99.85%", self.section_html)  # Test Recall

        # Check key classes in cards
        self.assertIn("Class 02 · DDoS", self.section_html)
        self.assertIn("Class 04 · DoS Hulk", self.section_html)
        self.assertIn("Class 03 · DoS GoldenEye", self.section_html)
        self.assertIn("Class 06 · DoS slowloris", self.section_html)
        self.assertIn("Class 05 · DoS Slowhttptest", self.section_html)
        self.assertIn("Class 13 · SQLi", self.section_html)
        self.assertIn("Class 14 · XSS", self.section_html)
        self.assertIn("Class 12 · Web Brute", self.section_html)
        self.assertIn("Class 11 · SSH-Patator", self.section_html)
        self.assertIn("Class 07 · FTP-Patator", self.section_html)
        self.assertIn("Class 08 · Heartbleed", self.section_html)
        self.assertIn("Class 10 · PortScan", self.section_html)
        self.assertIn("Class 01 · Bot", self.section_html)
        self.assertIn("Class 09 · Infiltration", self.section_html)

    def test_filter_tabs_and_controls_preserved(self):
        """Rule 5: Category tabs, filters, counters, and Auto-Patrol controls preserved."""
        self.assertIn('class="category-filter-bar"', self.section_html)
        self.assertIn('data-filter="all"', self.section_html)
        self.assertIn('data-filter="dos"', self.section_html)
        self.assertIn('data-filter="web"', self.section_html)
        self.assertIn('data-filter="brute"', self.section_html)
        self.assertIn('data-filter="recon"', self.section_html)

        self.assertIn('id="marqueeToggleBtn"', self.section_html)
        self.assertIn('id="sliderCurrentIndex"', self.section_html)
        self.assertIn('id="sliderTotalCount"', self.section_html)
        self.assertIn('id="attackCardContainer"', self.section_html)

    def test_css_styling_and_theme_support(self):
        """Rule 3, 4, 6: CSS Grid/flex dimensions, Lime Green accent, dark and light theme rules."""
        # Consistent card width
        self.assertIn("width: 320px;", self.css_content)
        self.assertIn("min-width: 320px;", self.css_content)
        self.assertIn("max-width: 320px;", self.css_content)

        # Attack card header & emblem styling
        self.assertIn(".attack-card-header", self.css_content)
        self.assertIn(".attack-icon-emblem", self.css_content)
        self.assertIn("var(--scout-lime)", self.css_content)

        # Light mode theme rule
        self.assertTrue(
            '[data-theme="light"] .attack-icon-emblem' in self.css_content or
            '[data-theme="light"]' in self.css_content,
            "Light theme support missing for attack icons"
        )

if __name__ == "__main__":
    unittest.main()
