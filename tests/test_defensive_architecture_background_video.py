import unittest
import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class TestDefensiveArchitectureBackgroundVideo(unittest.TestCase):
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

    def test_02_video_markup_in_defensive_architecture_section(self):
        """Verify the video markup is embedded inside .prevention-section (#prevention)."""
        section_match = re.search(r'<section\s+class="[^"]*prevention-section[^"]*"\s+id="prevention">([\s\S]*?)</section>', self.html)
        self.assertIsNotNone(section_match, "prevention-section (#prevention) must exist in ddos.html")
        section_content = section_match.group(1)

        # Check video tag and attributes
        self.assertIn('id="defensiveBgVideo"', section_content, "Video element must have id defensiveBgVideo")
        self.assertIn('class="defensive-bg-video"', section_content, "Video must have class defensive-bg-video")
        self.assertIn('autoplay', section_content, "Video must have autoplay attribute")
        self.assertIn('loop', section_content, "Video must have loop attribute")
        self.assertIn('muted', section_content, "Video must have muted attribute")
        self.assertIn('playsinline', section_content, "Video must have playsinline attribute")
        self.assertIn('poster="/static/images/attack-bg-poster.svg"', section_content, "Video must have fallback poster")
        self.assertIn('defensive-video-overlay', section_content, "Overlay element must exist within video backdrop")
        self.assertIn('/static/images/attack-bg.mp4', section_content, "Must reference web-safe static URL")
        self.assertIn('/static/images/WhatsApp%20Video%202026-10-25%20at%205.41.24%20PM.mp4', section_content, "Must reference WhatsApp video URL")

    def test_03_defensive_video_css_rules_and_pointer_events(self):
        """Verify CSS sets pointer-events: none, object-fit: cover, and proper stacking."""
        self.assertIn(".prevention-section", self.css)
        self.assertIn(".defensive-video-backdrop", self.css)
        self.assertIn(".defensive-bg-video", self.css)
        self.assertIn(".defensive-video-overlay", self.css)
        
        # Verify stacking & non-blocking interactions
        self.assertIn("user-select: none;", self.css)
        self.assertIn("pointer-events: none;", self.css)
        self.assertIn("object-fit: cover;", self.css)
        self.assertIn('[data-theme="dark"] .defensive-video-overlay', self.css)
        self.assertIn(".prevention-section .section-container", self.css)

    def test_04_js_initialization_and_silent_enforcement(self):
        """Verify main.js initializes defensive video and strictly enforces muting."""
        self.assertIn("function initDefensiveVideo()", self.js)
        self.assertIn("initDefensiveVideo();", self.js)
        self.assertIn('document.getElementById("defensiveBgVideo")', self.js)
        self.assertIn("video.muted = true;", self.js)
        self.assertIn("video.volume = 0;", self.js)

if __name__ == "__main__":
    unittest.main()
