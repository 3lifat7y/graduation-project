import unittest
import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class TestThreatIntelBackgroundVideo(unittest.TestCase):
    def setUp(self):
        self.html_path = os.path.join(BASE_DIR, "templates", "ddos.html")
        self.css_path = os.path.join(BASE_DIR, "static", "style.css")
        self.js_path = os.path.join(BASE_DIR, "static", "main.js")
        
        with open(self.html_path, "r", encoding="utf-8") as f:
            self.html = f.read()
        with open(self.css_path, "r", encoding="utf-8") as f:
            self.css = f.read()
        with open(self.js_path, "r", encoding="utf-8") as f:
            self.js = f.read()

    def test_01_video_asset_files_exist_and_not_empty(self):
        """Verify video assets exist in static/images and have non-zero size."""
        vid1 = os.path.join(BASE_DIR, "static", "images", "attack-bg.mp4")
        vid2 = os.path.join(BASE_DIR, "static", "images", "WhatsApp Video 2026-10-25 at 5.41.24 PM.mp4")
        poster = os.path.join(BASE_DIR, "static", "images", "attack-bg-poster.svg")
        
        self.assertTrue(os.path.exists(vid1), "attack-bg.mp4 must exist")
        self.assertGreater(os.path.getsize(vid1), 100000, "attack-bg.mp4 must not be empty")
        
        self.assertTrue(os.path.exists(vid2), "Original WhatsApp video must exist")
        self.assertGreater(os.path.getsize(vid2), 100000, "WhatsApp video must not be empty")
        
        self.assertTrue(os.path.exists(poster), "attack-bg-poster.svg fallback must exist")

    def test_02_video_markup_in_attack_classification_section(self):
        """Verify the video markup is embedded strictly inside #threat-intelligence section."""
        # Find section bounds
        section_match = re.search(r'<section\s+class="[^"]*threat-intel-section[^"]*"\s+id="threat-intelligence">([\s\S]*?)</section>', self.html)
        self.assertIsNotNone(section_match, "threat-intel-section (#threat-intelligence) must exist in ddos.html")
        section_content = section_match.group(1)

        # Check video tag and attributes
        self.assertIn('id="threatIntelBgVideo"', section_content, "Video element must have id threatIntelBgVideo")
        self.assertIn('class="threat-intel-bg-video"', section_content, "Video must have class threat-intel-bg-video")
        self.assertIn('autoplay', section_content, "Video must have autoplay attribute")
        self.assertIn('loop', section_content, "Video must have loop attribute")
        self.assertIn('muted', section_content, "Video must have muted attribute")
        self.assertIn('playsinline', section_content, "Video must have playsinline attribute")
        self.assertIn('poster="/static/images/attack-bg-poster.svg"', section_content, "Video must have fallback poster")
        self.assertIn('threat-intel-video-overlay', section_content, "Overlay element must exist within video backdrop")

    def test_03_css_rules_and_pointer_events(self):
        """Verify CSS sets pointer-events: none, object-fit: cover, and proper stacking."""
        self.assertIn(".threat-intel-section", self.css)
        self.assertIn(".threat-intel-video-backdrop", self.css)
        self.assertIn(".threat-intel-bg-video", self.css)
        self.assertIn(".threat-intel-video-overlay", self.css)
        
        # Verify pointer-events none
        self.assertIn("pointer-events: none;", self.css)
        # Verify object-fit cover
        self.assertIn("object-fit: cover;", self.css)
        # Verify dark mode overlay rule
        self.assertIn('[data-theme="dark"] .threat-intel-video-overlay', self.css)

    def test_04_js_initialization_and_silent_enforcement(self):
        """Verify main.js initializes threat intel video and strictly enforces muting."""
        self.assertIn("function initThreatIntelVideo()", self.js)
        self.assertIn("initThreatIntelVideo();", self.js)
        self.assertIn("video.muted = true;", self.js)
        self.assertIn("video.volume = 0;", self.js)
        self.assertIn("video.addEventListener(\"volumechange\"", self.js)

if __name__ == "__main__":
    unittest.main()
