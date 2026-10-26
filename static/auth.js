/**
 * SCOUT Standalone Authentication Controller
 * Handles Light/Dark Theme, Live Form Validation, Submission Lifecycles,
 * Rate-limit/Lockout feedback, and Session Integrity.
 */
(function() {
  "use strict";

  // ============================================================================
  // 1. Theme System Initialization & Persistence
  // ============================================================================
  function initAuthTheme() {
    const themeToggleBtn = document.getElementById("themeToggleBtn");
    const themeToggleIcon = document.getElementById("themeToggleIcon");
    const themeToggleText = document.getElementById("themeToggleText");
    const metaTheme = document.querySelector('meta[name="theme-color"]');

    function applyTheme(theme, animate = false) {
      if (animate) {
        document.body.classList.add("theme-transitioning");
      }
      document.documentElement.setAttribute("data-theme", theme);
      const isDark = theme === "dark";

      if (themeToggleIcon) {
        themeToggleIcon.className = isDark ? "fas fa-sun" : "fas fa-moon";
      }
      if (themeToggleText) {
        themeToggleText.textContent = isDark ? "Light Mode" : "Dark Mode";
      }
      if (themeToggleBtn) {
        const titleStr = isDark ? "Switch to Light Mode" : "Switch to Dark Mode";
        themeToggleBtn.setAttribute("title", titleStr);
        themeToggleBtn.setAttribute("aria-label", titleStr);
      }
      if (metaTheme) {
        metaTheme.setAttribute("content", isDark ? "#09090B" : "#FAFAFA");
      }

      if (animate) {
        window.setTimeout(() => {
          document.body.classList.remove("theme-transitioning");
        }, 260);
      }
    }

    const currentAttr = document.documentElement.getAttribute("data-theme");
    const savedTheme = localStorage.getItem("nss_theme");
    const systemDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const initialTheme = currentAttr || savedTheme || (systemDark ? "dark" : "light");
    applyTheme(initialTheme, false);

    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme") || "light";
        const next = current === "dark" ? "light" : "dark";
        localStorage.setItem("nss_theme", next);
        applyTheme(next, true);
      });
    }

    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
        if (!localStorage.getItem("nss_theme")) {
          applyTheme(e.matches ? "dark" : "light", true);
        }
      });
    }
  }

  // ============================================================================
  // 2. Alert Feedback Helper
  // ============================================================================
  const authAlert = document.getElementById("authAlert");
  const authAlertMessage = document.getElementById("authAlertMessage");
  const authAlertIcon = document.getElementById("authAlertIcon");

  function showAlert(message, type = "error") {
    if (!authAlert || !authAlertMessage) return;
    authAlert.className = `auth-alert ${type}`;
    authAlertMessage.textContent = message;

    if (authAlertIcon) {
      if (type === "success") {
        authAlertIcon.className = "auth-alert-icon fas fa-circle-check";
      } else if (type === "info") {
        authAlertIcon.className = "auth-alert-icon fas fa-circle-info";
      } else {
        authAlertIcon.className = "auth-alert-icon fas fa-circle-exclamation";
      }
    }
    authAlert.style.display = "flex";
    authAlert.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function hideAlert() {
    if (authAlert) {
      authAlert.style.display = "none";
      authAlert.className = "auth-alert";
    }
  }

  // ============================================================================
  // 3. Existing Session Detection (Non-destructive)
  // ============================================================================
  async function checkCurrentSession() {
    try {
      const res = await fetch("/api/auth/me", { credentials: "same-origin" });
      if (res.ok) {
        const data = await res.json();
        const user = data.user;
        if (user) {
          const banner = document.getElementById("authSessionBanner");
          const text = document.getElementById("authSessionText");
          const link = document.getElementById("authSessionLink");

          if (banner && text) {
            text.textContent = `Signed in as ${user.full_name || user.username} (${user.role}).`;
            if (link) {
              if (user.role === "Admin") {
                link.setAttribute("href", "/?view=admin");
                link.textContent = "Go to Admin Console \u2192";
              } else {
                link.setAttribute("href", "/?view=dashboard");
                link.textContent = "Go to Dashboard \u2192";
              }
            }
            banner.style.display = "flex";
          }
        }
      }
    } catch (_) {
      // Offline / unauthenticated — expected state for login/register visitors
    }
  }

  // Check for any notification passed from Homepage actions
  function checkPendingNotices() {
    const notice = sessionStorage.getItem("scout_auth_notice");
    if (notice) {
      showAlert(notice, "info");
      sessionStorage.removeItem("scout_auth_notice");
    }

    const urlParams = new URLSearchParams(window.location.search);
    const urlNotice = urlParams.get("notice");
    if (urlNotice) {
      showAlert(urlNotice, "info");
    }
  }

  // ============================================================================
  // 4. Password Visibility Toggles
  // ============================================================================
  function initPasswordToggles() {
    const toggleSignInPwd = document.getElementById("togglePasswordBtn");
    if (toggleSignInPwd) {
      toggleSignInPwd.addEventListener("click", () => {
        const pwdInput = document.getElementById("loginPassword");
        const icon = document.getElementById("togglePasswordIcon");
        if (pwdInput) {
          const isPwd = pwdInput.type === "password";
          pwdInput.type = isPwd ? "text" : "password";
          if (icon) {
            icon.className = isPwd ? "fas fa-eye-slash" : "fas fa-eye";
          }
        }
      });
    }

    const toggleRegPwd = document.getElementById("toggleRegPwd");
    if (toggleRegPwd) {
      toggleRegPwd.addEventListener("click", () => {
        const pwdInput = document.getElementById("regPassword");
        const icon = document.getElementById("toggleRegPwdIcon");
        if (pwdInput) {
          const isPwd = pwdInput.type === "password";
          pwdInput.type = isPwd ? "text" : "password";
          if (icon) {
            icon.className = isPwd ? "fas fa-eye-slash" : "fas fa-eye";
          }
        }
      });
    }
  }

  // ============================================================================
  // 5. Real-Time Password Complexity Guidance (Register Page)
  // ============================================================================
  function initPasswordStrengthValidation() {
    const regPassword = document.getElementById("regPassword");
    const regConfirm = document.getElementById("regConfirmPassword");
    const ruleLength = document.getElementById("pwdRuleLength");
    const ruleCase = document.getElementById("pwdRuleCase");
    const ruleNumSpecial = document.getElementById("pwdRuleNumSpecial");

    if (!regPassword) return;

    function evaluateRules() {
      const val = regPassword.value || "";

      // 1. Min 8 characters
      const lenOk = val.length >= 8;
      updateRuleState(ruleLength, lenOk);

      // 2. Uppercase & lowercase
      const caseOk = /[A-Z]/.test(val) && /[a-z]/.test(val);
      updateRuleState(ruleCase, caseOk);

      // 3. Number & special character
      const numSpecialOk = /\d/.test(val) && /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val);
      updateRuleState(ruleNumSpecial, numSpecialOk);

      return lenOk && caseOk && numSpecialOk;
    }

    function updateRuleState(element, isValid) {
      if (!element) return;
      const icon = element.querySelector("i");
      if (isValid) {
        element.classList.add("valid");
        if (icon) icon.className = "fas fa-circle-check guidance-icon";
      } else {
        element.classList.remove("valid");
        if (icon) icon.className = "fas fa-circle-dot guidance-icon";
      }
    }

    regPassword.addEventListener("input", evaluateRules);
    if (regConfirm) {
      regConfirm.addEventListener("input", () => {
        if (regConfirm.value && regPassword.value && regConfirm.value !== regPassword.value) {
          regConfirm.classList.add("has-error");
        } else {
          regConfirm.classList.remove("has-error");
        }
      });
    }
  }

  // ============================================================================
  // 6. Login Form Submission Handler
  // ============================================================================
  function initLoginForm() {
    const form = document.getElementById("loginForm");
    if (!form) return;

    const identifierInput = document.getElementById("loginIdentifier");
    const passwordInput = document.getElementById("loginPassword");
    const submitBtn = document.getElementById("loginSubmitBtn");
    const spinner = document.getElementById("loginSpinner");
    const btnText = document.getElementById("loginBtnText");
    const btnIcon = document.getElementById("loginBtnIcon");

    function setSubmittingState(isSubmitting) {
      if (!submitBtn) return;
      submitBtn.disabled = isSubmitting;
      if (spinner) spinner.style.display = isSubmitting ? "inline-block" : "none";
      if (btnIcon) btnIcon.style.display = isSubmitting ? "none" : "inline-block";
      if (btnText) btnText.textContent = isSubmitting ? "Signing in..." : "Sign In";
      if (identifierInput) identifierInput.disabled = isSubmitting;
      if (passwordInput) passwordInput.disabled = isSubmitting;
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAlert();

      const identifier = identifierInput ? identifierInput.value.trim() : "";
      const password = passwordInput ? passwordInput.value : "";

      if (!identifier || !password) {
        showAlert("Please enter your email or phone number and password.", "error");
        if (!identifier && identifierInput) identifierInput.focus();
        else if (passwordInput) passwordInput.focus();
        return;
      }

      setSubmittingState(true);

      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ identifier: identifier, password: password })
        });

        const data = await res.json().catch(() => ({}));

        if (res.ok && data.status === "success") {
          showAlert("Authentication successful. Redirecting...", "success");

          // Determine post-login destination URL
          const urlParams = new URLSearchParams(window.location.search);
          const redirectParam = urlParams.get("redirect") || urlParams.get("next");

          let destination = data.redirect;
          if (redirectParam && redirectParam.startsWith("/")) {
            destination = redirectParam;
          } else if (!destination) {
            if (data.view) {
              destination = `/?view=${encodeURIComponent(data.view)}`;
            } else if (data.user && data.user.role === "Admin") {
              destination = "/?view=admin";
            } else {
              destination = "/?view=dashboard";
            }
          }

          window.setTimeout(() => {
            window.location.href = destination;
          }, 350);
        } else {
          setSubmittingState(false);
          const errMsg = data.message || "Invalid credentials.";
          showAlert(errMsg, "error");
          if (passwordInput) {
            passwordInput.value = "";
            passwordInput.focus();
          }
        }
      } catch (err) {
        setSubmittingState(false);
        showAlert("Network error: Unable to connect to authentication server. Please check your network connection.", "error");
      }
    });
  }

  // ============================================================================
  // 7. Register Form Submission Handler
  // ============================================================================
  function initRegisterForm() {
    const form = document.getElementById("registerForm");
    if (!form) return;

    const fullNameInput = document.getElementById("regFullName");
    const emailInput = document.getElementById("regEmail");
    const phoneInput = document.getElementById("regPhone");
    const passwordInput = document.getElementById("regPassword");
    const confirmInput = document.getElementById("regConfirmPassword");

    const submitBtn = document.getElementById("registerSubmitBtn");
    const spinner = document.getElementById("registerSpinner");
    const btnText = document.getElementById("registerBtnText");
    const btnIcon = document.getElementById("registerBtnIcon");

    function setSubmittingState(isSubmitting) {
      if (!submitBtn) return;
      submitBtn.disabled = isSubmitting;
      if (spinner) spinner.style.display = isSubmitting ? "inline-block" : "none";
      if (btnIcon) btnIcon.style.display = isSubmitting ? "none" : "inline-block";
      if (btnText) btnText.textContent = isSubmitting ? "Creating Account..." : "Create Account";
      if (fullNameInput) fullNameInput.disabled = isSubmitting;
      if (emailInput) emailInput.disabled = isSubmitting;
      if (phoneInput) phoneInput.disabled = isSubmitting;
      if (passwordInput) passwordInput.disabled = isSubmitting;
      if (confirmInput) confirmInput.disabled = isSubmitting;
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAlert();

      const fullName = fullNameInput ? fullNameInput.value.trim() : "";
      const email = emailInput ? emailInput.value.trim().toLowerCase() : "";
      const phone = phoneInput ? phoneInput.value.trim() : "";
      const password = passwordInput ? passwordInput.value : "";
      const confirmPassword = confirmInput ? confirmInput.value : "";

      // Client-side validations
      if (!fullName || !email || !phone || !password || !confirmPassword) {
        showAlert("Please fill in all required fields.", "error");
        return;
      }

      if (fullName.length < 2) {
        showAlert("Please enter your full name.", "error");
        if (fullNameInput) fullNameInput.focus();
        return;
      }

      if (!/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(email)) {
        showAlert("Please enter a valid email address.", "error");
        if (emailInput) emailInput.focus();
        return;
      }

      // Validate phone number format (E.164: 7-15 digits with optional leading +)
      const cleanedPhone = phone.replace(/[\s\-\.\(\)]/g, "");
      const digitsPart = cleanedPhone.startsWith("+") ? cleanedPhone.slice(1) : (cleanedPhone.startsWith("00") ? cleanedPhone.slice(2) : cleanedPhone);
      if (!/^\d{7,15}$/.test(digitsPart)) {
        showAlert("Please enter a valid phone number (7-15 digits, international format supported).", "error");
        if (phoneInput) phoneInput.focus();
        return;
      }

      if (password !== confirmPassword) {
        showAlert("Password and confirmation password do not match.", "error");
        if (confirmInput) confirmInput.focus();
        return;
      }

      if (password.length < 8) {
        showAlert("Password must be at least 8 characters long.", "error");
        if (passwordInput) passwordInput.focus();
        return;
      }

      if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
        showAlert("Password must include both uppercase and lowercase letters.", "error");
        if (passwordInput) passwordInput.focus();
        return;
      }

      if (!/\d/.test(password)) {
        showAlert("Password must include at least one numeric digit (0-9).", "error");
        if (passwordInput) passwordInput.focus();
        return;
      }

      if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        showAlert("Password must include at least one special character.", "error");
        if (passwordInput) passwordInput.focus();
        return;
      }

      setSubmittingState(true);

      try {
        const res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            full_name: fullName,
            email: email,
            phone_number: phone,
            password: password,
            confirm_password: confirmPassword
          })
        });

        const data = await res.json().catch(() => ({}));

        if (res.ok && data.status === "success") {
          showAlert("Account created successfully! Preparing your security environment...", "success");
          const destination = data.redirect || "/?view=plans";
          window.setTimeout(() => {
            window.location.href = destination;
          }, 450);
        } else {
          setSubmittingState(false);
          const errMsg = data.message || "Failed to create account. Please try again.";
          showAlert(errMsg, "error");
        }
      } catch (err) {
        setSubmittingState(false);
        showAlert("Network error: Unable to connect to registration server. Please check your connection.", "error");
      }
    });
  }


  // ============================================================================
  // Initialize Everything on DOMContentLoaded
  // ============================================================================
  document.addEventListener("DOMContentLoaded", () => {
    initAuthTheme();
    initPasswordToggles();
    initPasswordStrengthValidation();
    initLoginForm();
    initRegisterForm();
    checkCurrentSession();
    checkPendingNotices();
  });
})();
