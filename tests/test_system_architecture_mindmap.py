import unittest
import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class TestSystemArchitectureMindMap(unittest.TestCase):
    def setUp(self):
        self.html_path = os.path.join(BASE_DIR, "templates", "ddos.html")
        self.css_path = os.path.join(BASE_DIR, "static", "style.css")
        self.js_path = os.path.join(BASE_DIR, "static", "mindmap.js")
        
        with open(self.html_path, "r", encoding="utf-8") as f:
            self.html = f.read()
        with open(self.css_path, "r", encoding="utf-8") as f:
            self.css = f.read()
        with open(self.js_path, "r", encoding="utf-8") as f:
            self.js = f.read()

    def test_01_section_integration_in_home_page(self):
        """Verify #system-architecture exists as a dedicated section in ddos.html."""
        self.assertIn('id="system-architecture"', self.html)
        self.assertIn('class="system-architecture-section"', self.html)
        self.assertIn("SCOUT Architecture & Operations Mind Map", self.html)

    def test_02_pure_code_generation_not_static_image(self):
        """Verify the mind map is rendered from HTML/SVG/CSS without reference image embedding."""
        section_match = re.search(r'<section\s+class="[^"]*system-architecture-section[^"]*"\s+id="system-architecture">([\s\S]*?)</section>', self.html)
        self.assertIsNotNone(section_match)
        content = section_match.group(1)
        
        # Verify no reference screenshot or mind map image is used as the content
        self.assertNotIn("media_", content)
        self.assertNotIn(".jpg", content)
        
        # Verify actual DOM nodes and SVG canvas are present
        self.assertIn('id="mindmapSvg"', content)
        self.assertIn('class="mindmap-canvas"', content)

    def test_03_central_scout_core_node(self):
        """Verify Central Node displays official SCOUT logo, name SCOUT, and subtitle."""
        self.assertIn('id="mmNodeCore"', self.html)
        self.assertIn('class="mm-core-title">SCOUT</div>', self.html)
        self.assertIn('AUTONOMOUS NETWORK DEFENSE', self.html)
        self.assertIn('/static/images/scout-icon.png', self.html)
        self.assertIn('/static/images/scout-icon-dark.png', self.html)

    def test_04_four_major_branches_present(self):
        """Verify all 4 major branches (Live Monitoring, Port Scanner, Attack Classes, Network Discovery)."""
        self.assertIn('id="mmBranchMonitoring"', self.html)
        self.assertIn('Live Monitoring', self.html)
        
        self.assertIn('id="mmBranchPortscan"', self.html)
        self.assertIn('Port Scanner', self.html)
        
        self.assertIn('id="mmBranchAttacks"', self.html)
        self.assertIn('Attack Classes', self.html)
        
        self.assertIn('id="mmBranchDiscovery"', self.html)
        self.assertIn('Network Discovery', self.html)

    def test_05_all_sixteen_child_nodes_verified(self):
        """Verify all 16 child nodes from reference diagram are represented with verified details."""
        # Branch 1 (Monitoring)
        self.assertIn('Packet Capture', self.html)
        self.assertIn('Npcap · passive sniffing', self.html)
        self.assertIn('Feature Extraction', self.html)
        self.assertIn('77 bidirectional features', self.html)
        self.assertIn('XGBoost Classifier', self.html)
        self.assertIn('15 classes · CIC-IDS2017', self.html)
        self.assertIn('Verdict', self.html)
        self.assertIn('class · confidence score', self.html)

        # Branch 2 (Port Scanner)
        self.assertIn('Localhost', self.html)
        self.assertIn('127.0.0.1 loopback', self.html)
        self.assertIn('Single Target', self.html)
        self.assertIn('one IP address', self.html)
        self.assertIn('Subnet Scan', self.html)
        self.assertIn('CIDR /24', self.html)
        self.assertIn('Export', self.html)
        self.assertIn('JSON · CSV', self.html)

        # Branch 3 (Attack Classes)
        self.assertIn('Denial of Service · 5', self.html)
        self.assertIn('DDoS · Hulk · GoldenEye +2', self.html)
        self.assertIn('Web Attacks · 3', self.html)
        self.assertIn('SQLi · XSS · Brute Force', self.html)
        self.assertIn('Brute Force & Exploits · 3', self.html)
        self.assertIn('SSH · FTP · Heartbleed', self.html)
        self.assertIn('Recon & Infiltration · 3', self.html)
        self.assertIn('Portscan · Bot · Infiltration', self.html)

        # Branch 4 (Network Discovery)
        self.assertIn('ARP + ICMP Sweep', self.html)
        self.assertIn('non-intrusive probing', self.html)
        self.assertIn('MAC & OUI Vendor', self.html)
        self.assertIn('hardware fingerprint', self.html)
        self.assertIn('Device Types', self.html)
        self.assertIn('router · PC · mobile · IoT', self.html)
        self.assertIn('Inventory Views', self.html)
        self.assertIn('cards & table', self.html)

    def test_06_interactive_controls_present(self):
        """Verify Zoom In, Zoom Out, Fit, Reset, and Toggle Branch controls exist."""
        self.assertIn('id="mmZoomInBtn"', self.html)
        self.assertIn('id="mmZoomOutBtn"', self.html)
        self.assertIn('id="mmFitBtn"', self.html)
        self.assertIn('id="mmResetBtn"', self.html)
        self.assertIn('id="mmToggleAllBranchesBtn"', self.html)
        self.assertIn('id="mindmapDetailsDrawer"', self.html)

    def test_07_css_branch_colors_and_dark_mode(self):
        """Verify CSS contains branch-specific color tokens and dark theme support."""
        self.assertIn('.mm-node-teal', self.css)
        self.assertIn('.mm-node-amber', self.css)
        self.assertIn('.mm-node-coral', self.css)
        self.assertIn('.mm-node-blue', self.css)
        
        self.assertIn('[data-theme="dark"] .mm-node-teal', self.css)
        self.assertIn('[data-theme="dark"] .mm-node-amber', self.css)
        self.assertIn('[data-theme="dark"] .mm-node-coral', self.css)
        self.assertIn('[data-theme="dark"] .mm-node-blue', self.css)

    def test_08_js_controller_registered_and_script_included(self):
        """Verify mindmap.js contains initialization, pan/zoom, dynamic SVG connector math."""
        self.assertIn('src="/static/mindmap.js"', self.html)
        self.assertIn('function renderSvgConnectors()', self.js)
        self.assertIn('function applyTransform()', self.js)
        self.assertIn('function selectNode(', self.js)
        self.assertIn('function toggleBranch(', self.js)

if __name__ == "__main__":
    unittest.main()
