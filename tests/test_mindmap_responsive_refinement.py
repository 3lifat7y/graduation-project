import os
import re
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class TestMindMapResponsiveRefinement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html_path = os.path.join(BASE_DIR, "templates", "ddos.html")
        cls.css_path = os.path.join(BASE_DIR, "static", "style.css")
        cls.js_path = os.path.join(BASE_DIR, "static", "mindmap.js")

        with open(cls.html_path, "r", encoding="utf-8") as f:
            cls.html = f.read()
        with open(cls.css_path, "r", encoding="utf-8") as f:
            cls.css = f.read()
        with open(cls.js_path, "r", encoding="utf-8") as f:
            cls.js = f.read()

    def test_01_no_mouse_wheel_zoom_handlers(self):
        """Rule 1: Verify mouse-wheel event listeners and scale hijacking are completely removed."""
        self.assertNotIn('addEventListener("wheel"', self.js)
        self.assertNotIn("addEventListener('wheel'", self.js)
        self.assertNotIn("e.deltaY", self.js)

    def test_02_no_canvas_drag_to_pan(self):
        """Rule 1: Verify mousedown/mousemove canvas dragging and grabbing cursors are disabled."""
        self.assertNotIn('viewport.addEventListener("mousedown"', self.js)
        self.assertNotIn("cursor: grab", self.css)
        self.assertNotIn("cursor: grabbing", self.css)
        self.assertNotIn("is-dragging", self.js)

    def test_03_no_forced_canvas_transform_scaling(self):
        """Rule 2: Canvas uses transform: none !important and does not scale arbitrarily."""
        self.assertIn("transform: none !important;", self.css)
        self.assertIn('canvas.style.transform = "none"', self.js)

    def test_04_desktop_layout_stability(self):
        """Rule 2 & 3: Desktop layout has balanced max-width, relative positioning, and centered core."""
        self.assertIn(".mindmap-canvas", self.css)
        self.assertIn("max-width: 1240px;", self.css)
        self.assertIn("margin: 0 auto;", self.css)
        self.assertIn(".mm-col-center", self.css)
        self.assertIn(".mm-node-core", self.css)

    def test_05_tablet_responsive_breakpoint(self):
        """Rule 3: Tablet breakpoint (768px - 1100px) reduces spacing and node widths proportionally."""
        self.assertIn("@media (min-width: 768px) and (max-width: 1100px)", self.css)
        self.assertIn(".mm-col-left-children", self.css)
        self.assertIn(".mm-col-left-branches", self.css)
        self.assertIn(".mm-col-right-branches", self.css)
        self.assertIn(".mm-col-right-children", self.css)

    def test_06_mobile_structured_tree_layout(self):
        """Rule 3: Mobile breakpoint (<768px) adapts into vertically stacked tree with order hierarchy."""
        self.assertIn("@media (max-width: 767px)", self.css)
        self.assertIn(".mm-column", self.css)
        self.assertIn("display: contents;", self.css)
        self.assertIn("order: 1;", self.css)
        self.assertIn("order: 2;", self.css)
        self.assertIn("order: 3;", self.css)
        # Verify narrow mobile (<420px for 360x800 and 390x844) grid single-column adaptation
        self.assertIn("@media (max-width: 420px)", self.css)
        self.assertIn("grid-template-columns: 1fr;", self.css)

    def test_07_node_selection_and_drawer_preserved(self):
        """Rule 4: Clicking nodes still opens detail drawer with verified metadata."""
        self.assertIn("selectNode(id)", self.js)
        self.assertIn("mindmapDetailsDrawer", self.html)
        self.assertIn("drawer.style.display = \"flex\";", self.js)

    def test_08_theme_compatibility(self):
        """Rule 4: Dark mode styling is maintained across container, nodes, and connectors."""
        self.assertIn('[data-theme="dark"] .mindmap-viewport', self.css)
        self.assertIn('[data-theme="dark"] .mm-node-core', self.css)
        self.assertIn('[data-theme="dark"] .mm-connector-teal', self.css)

if __name__ == "__main__":
    unittest.main()
