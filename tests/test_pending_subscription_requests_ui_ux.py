"""
SCOUT - Pending Subscription Requests Page UI/UX Test Suite
Validates:
1. Wider, compact request cards with standardized padding, proper spacing, and amber theme accent.
2. Responsive grid system: multiple cards per row on desktop (both with expanded and collapsed sidebars),
   adapting smoothly to smaller screens and container sizes.
3. Clean information architecture:
   - Applicant header with avatar, username, email, and Pending Approval status badge with #ID chip.
   - Requested Plan banner with tier name and pricing.
   - Structured key-value data grid with Request Date, Subscription ID, Payment Method, Receiving Account,
     Transaction Reference, and Payment Receipt indicator.
4. Prevention of text overlap, unnecessary wrapping, and horizontal scrolling:
   - min-width: 0 and text-overflow: ellipsis on text fields.
   - Monospace typography on receiving accounts and transaction reference codes.
   - Tooltips (title attributes) on truncated values.
5. Proper button alignment across Details, View Receipt, Approve, Reject, and Delete:
   - Unified button grid in card footer.
   - Uniform button heights, padding, font size, and border radius.
   - View Receipt button rendered interactively when receipt is present and disabled-locked when absent.
   - Semantic color schemes in both dark mode and light mode matching SCOUT theme.
6. Functional integrity:
   - Event listener bindings for details dossier, activation/approval, rejection, deletion, and receipt viewer.
   - Fallback table synchronization for legacy references.
   - Admin pending request count badge in panel header.
"""

import os
import re
import unittest

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STYLE_CSS_PATH = os.path.join(WORKSPACE_DIR, "static", "style.css")
DDOS_HTML_PATH = os.path.join(WORKSPACE_DIR, "templates", "ddos.html")
MAIN_JS_PATH = os.path.join(WORKSPACE_DIR, "static", "main.js")


class TestPendingSubscriptionRequestsUIUX(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(STYLE_CSS_PATH, "r", encoding="utf-8") as f:
            cls.css = f.read()
        with open(DDOS_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()
        with open(MAIN_JS_PATH, "r", encoding="utf-8") as f:
            cls.js = f.read()

    # =========================================================================
    # 1. Responsive Grid & Multi-Column Desktop Layout
    # =========================================================================
    def test_01_card_container_has_inline_size_container_type(self):
        """Container must declare container-type: inline-size for responsive container queries."""
        pattern = re.compile(
            r"\.admin-requests-card-container\s*\{[^}]*container-type:\s*inline-size",
            re.DOTALL,
        )
        self.assertTrue(pattern.search(self.css), ".admin-requests-card-container must declare container-type: inline-size")

    def test_02_desktop_grid_multiple_cards_per_row_collapsed_sidebar(self):
        """When sidebar is collapsed, desktop grid must display multiple cards per row (2-3 columns)."""
        pattern = re.compile(
            r"body\.sidebar-collapsed[^{}]*\.admin-requests-cards-grid[^{}]*\{[^}]*grid-template-columns:\s*repeat\([23],",
            re.DOTALL,
        )
        self.assertTrue(pattern.search(self.css), "Collapsed sidebar should have 2-3 columns on desktop")

    def test_03_desktop_grid_multiple_cards_per_row_expanded_sidebar(self):
        """When sidebar is expanded, desktop grid must display multiple cards per row (2-3 columns)."""
        pattern = re.compile(
            r"body:not\(\.sidebar-collapsed\)[^{}]*\.admin-requests-cards-grid[^{}]*\{[^}]*grid-template-columns:\s*repeat\([23],",
            re.DOTALL,
        )
        self.assertTrue(pattern.search(self.css), "Expanded sidebar should have 2-3 columns on desktop")

    def test_04_responsive_grid_single_column_on_smaller_screens(self):
        """Cards grid should adapt to 1 column on tablet and mobile screens (<= 860px)."""
        pattern = re.compile(
            r"@media\s*\(\s*max-width:\s*860px\s*\)\s*\{[^}]*\.admin-requests-cards-grid[^{}]*\{[^}]*grid-template-columns:\s*1fr",
            re.DOTALL,
        )
        self.assertTrue(pattern.search(self.css), "Grid must scale down to 1fr on max-width: 860px")

    def test_05_container_adaptive_fluid_queries(self):
        """Grid must declare @container fluid rules for adaptive card columns."""
        self.assertIn("@container (min-width: 1240px)", self.css)
        self.assertIn("@container (min-width: 700px)", self.css)
        self.assertIn("@container (max-width: 699px)", self.css)

    # =========================================================================
    # 2. Card Dimensions, Proper Padding, Spacing, and SCOUT Theme
    # =========================================================================
    def test_06_request_card_compact_dimensions_and_padding(self):
        """Request cards must have standardized 20px padding and 12px border radius."""
        card_pattern = re.compile(r"\.admin-request-card\s*\{([^}]+)\}", re.DOTALL)
        match = card_pattern.search(self.css)
        self.assertIsNotNone(match, ".admin-request-card rule must exist")
        body = match.group(1)
        self.assertIn("padding: 20px 20px;", body)
        self.assertIn("border-radius: 12px;", body)
        self.assertIn("overflow: hidden;", body)
        self.assertIn("min-width: 0;", body)

    def test_07_request_card_amber_top_border_indicator(self):
        """Request card must have amber accent indicator line indicating pending review state."""
        border_pattern = re.compile(r"\.admin-request-card::before\s*\{([^}]+)\}", re.DOTALL)
        match = border_pattern.search(self.css)
        self.assertIsNotNone(match, ".admin-request-card::before must exist")
        body = match.group(1)
        self.assertIn("#F59E0B", body)
        self.assertIn("height: 3px;", body)

    def test_08_request_card_header_spacing(self):
        """Header must have 12px bottom margin to maintain proper vertical rhythm."""
        hdr_pattern = re.compile(r"\.request-card-header\s*\{([^}]+)\}", re.DOTALL)
        match = hdr_pattern.search(self.css)
        self.assertIsNotNone(match, ".request-card-header must exist")
        self.assertIn("margin-bottom: 12px;", match.group(1))

    # =========================================================================
    # 3. Clean Information Architecture & Layout
    # =========================================================================
    def test_09_plan_highlight_banner_styling(self):
        """Plan banner must prominently display requested tier and price."""
        self.assertIn(".request-plan-banner", self.css)
        self.assertIn(".request-plan-icon", self.css)
        self.assertIn(".request-plan-name", self.css)
        self.assertIn(".request-plan-price", self.css)
        # Template markup in main.js
        self.assertIn('class="request-plan-banner"', self.js)
        self.assertIn('class="request-plan-icon"', self.js)
        self.assertIn('class="request-plan-name"', self.js)
        self.assertIn('class="request-plan-price"', self.js)

    def test_10_request_telemetry_data_grid(self):
        """Data grid must organize Request Date, Sub ID, Payment Method, Account, Tx Ref, and Receipt."""
        self.assertIn(".request-data-grid", self.css)
        self.assertIn(".request-data-item", self.css)
        self.assertIn(".request-data-label", self.css)
        self.assertIn(".request-data-val", self.css)
        self.assertIn(".receipt-indicator-pill", self.css)
        # In main.js
        self.assertIn("Requested Tier", self.js)
        self.assertIn("Request Date", self.js)
        self.assertIn("Payment Method", self.js)
        self.assertIn("Receiving Account", self.js)
        self.assertIn("Tx Reference", self.js)
        self.assertIn("Payment Receipt", self.js)

    # =========================================================================
    # 4. Text Overlap Prevention & Overflow Safeguards
    # =========================================================================
    def test_11_text_overflow_truncation_and_ellipsis(self):
        """Username, email, and values must have text-overflow: ellipsis to prevent blowout."""
        user_pattern = re.compile(r"\.request-username\s*\{([^}]+)\}", re.DOTALL)
        match_user = user_pattern.search(self.css)
        self.assertIsNotNone(match_user)
        self.assertIn("text-overflow: ellipsis;", match_user.group(1))
        self.assertIn("white-space: nowrap;", match_user.group(1))

        val_pattern = re.compile(r"\.request-data-val\s*\{([^}]+)\}", re.DOTALL)
        match_val = val_pattern.search(self.css)
        self.assertIsNotNone(match_val)
        self.assertIn("text-overflow: ellipsis;", match_val.group(1))
        self.assertIn("white-space: nowrap;", match_val.group(1))

    def test_12_monospace_data_values(self):
        """Receiving accounts and transaction references must be styled with monospace font."""
        mono_pattern = re.compile(r"\.request-data-val\.font-mono\s*\{([^}]+)\}", re.DOTALL)
        match_mono = mono_pattern.search(self.css)
        self.assertIsNotNone(match_mono)
        self.assertIn("font-family: var(--font-mono", match_mono.group(1))

    # =========================================================================
    # 5. Proper Button Alignment (Details, View Receipt, Approve, Reject, Delete)
    # =========================================================================
    def test_13_button_grid_layout_in_footer(self):
        """Card footer must use .request-btn-grid to align Details, Receipt, Approve, Reject, and Delete."""
        self.assertIn(".request-btn-grid", self.css)
        self.assertIn('class="request-btn-grid"', self.js)

        # Unified button heights and styles
        btn_grid_rule = re.compile(r"\.request-btn-grid\s+\.btn-admin-action\s*\{([^}]+)\}", re.DOTALL)
        match_btns = btn_grid_rule.search(self.css)
        self.assertIsNotNone(match_btns)
        body = match_btns.group(1)
        self.assertIn("height: 34px;", body)
        self.assertIn("border-radius: 6px;", body)

    def test_14_view_receipt_button_states(self):
        """View receipt button must have receipt semantic class and handle attached vs disabled state."""
        self.assertIn(".btn-admin-action.receipt", self.css)
        # Interactive state in main.js when receipt_url is truthy
        self.assertIn('class="btn-admin-action receipt"', self.js)
        # Disabled-locked state when receipt_url is absent
        self.assertIn('class="btn-admin-action receipt disabled-locked"', self.js)
        # Verify disabled attribute is set when no receipt
        self.assertIn('disabled title="No payment receipt attached"', self.js)

    def test_15_light_theme_fidelity_for_request_cards(self):
        """Light theme must have high contrast overrides for cards, badges, banners, and receipt button."""
        self.assertIn('[data-theme="light"] .admin-request-card', self.css)
        self.assertIn('[data-theme="light"] .request-username', self.css)
        self.assertIn('[data-theme="light"] .request-data-val', self.css)
        self.assertIn('[data-theme="light"] .request-plan-banner', self.css)
        self.assertIn('[data-theme="light"] .request-data-grid', self.css)
        self.assertIn('[data-theme="light"] .btn-admin-action.receipt', self.css)

    # =========================================================================
    # 6. Functional & DOM Integrity
    # =========================================================================
    def test_16_pending_count_badge_in_panel_header(self):
        """ddos.html must include #adminPendingCountBadge in the pending requests panel header."""
        self.assertIn('id="adminPendingCountBadge"', self.html)
        self.assertIn('id="refreshRequestsBtn"', self.html)
        self.assertIn('id="adminRequestsCardsGrid"', self.html)
        self.assertIn('id="adminRequestsTable"', self.html)
        self.assertIn('id="adminRequestsTbody"', self.html)

    def test_17_action_event_binding_attributes_preserved(self):
        """main.js must bind all required action attributes: details, act, rej, delete, and view-receipt."""
        self.assertIn("[data-sub-details-id]", self.js)
        self.assertIn("[data-act-id]", self.js)
        self.assertIn("[data-rej-id]", self.js)
        self.assertIn("[data-sub-delete-id]", self.js)
        self.assertIn("[data-view-receipt]", self.js)


if __name__ == "__main__":
    unittest.main()
