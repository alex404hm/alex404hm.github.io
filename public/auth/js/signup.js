document.addEventListener('DOMContentLoaded', () => {
    const signupForm = document.getElementById('signup-form');
    const signupButton = document.getElementById('signup-button');
    const spinner = document.getElementById('spinner');
    const nameError = document.getElementById('name-error');
    const emailError = document.getElementById('email-error');
    const phoneError = document.getElementById('phone-error');
    const passwordError = document.getElementById('password-error');
    const confirmPasswordError = document.getElementById('confirm-password-error');
    const generalError = document.getElementById('general-error');
    const phoneInput = document.getElementById('phone');

    function formatPhoneNumber(value) {
        let cleaned = value.replace(/[^\d+]/g, '');
        if (cleaned.startsWith('+45')) {
            cleaned = '+45 ' + cleaned.slice(3);
            cleaned = cleaned.replace(/(\d{2})(?=\d)/g, '$1 ');
        } else {
            cleaned = cleaned.replace(/(\d{2})(?=\d)/g, '$1 ');
        }
        return cleaned.trim();
    }

    phoneInput.addEventListener('input', (e) => {
        const cursorPosition = phoneInput.selectionStart;
        const originalLength = phoneInput.value.length;
        phoneInput.value = formatPhoneNumber(phoneInput.value);
        const newLength = phoneInput.value.length;
        phoneInput.setSelectionRange(cursorPosition + (newLength > originalLength ? 1 : -1), cursorPosition + (newLength > originalLength ? 1 : -1));
    });

    signupForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const name = signupForm.name.value.trim();
        const email = signupForm.email.value.trim();
        const phone = signupForm.phone.value.trim();
        const password = signupForm.password.value.trim();
        const confirmPassword = signupForm['confirm-password'].value.trim();

        [nameError, emailError, phoneError, passwordError, confirmPasswordError, generalError].forEach(el => el.textContent = '');

        let hasError = false;

        if (!name) {
            nameError.textContent = 'Indtast venligst dit navn.';
            hasError = true;
        }

        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email || !emailPattern.test(email)) {
            emailError.textContent = 'Indtast venligst en gyldig e-mail.';
            hasError = true;
        }

        const phonePattern = /^\+45\s\d{2}\s\d{2}\s\d{2}\s\d{2}$/;
        if (!phone || !phonePattern.test(phone)) {
            phoneError.textContent = 'Indtast venligst et gyldigt telefonnummer (f.eks. +45 12 34 56 78).';
            hasError = true;
        }

        if (!password) {
            passwordError.textContent = 'Indtast venligst din adgangskode.';
            hasError = true;
        } else if (password.length < 8) {
            passwordError.textContent = 'Adgangskoden skal være mindst 8 tegn lang.';
            hasError = true;
        } else if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
            passwordError.textContent = 'Adgangskoden skal indeholde både store og små bogstaver samt tal.';
            hasError = true;
        }

        if (password !== confirmPassword) {
            confirmPasswordError.textContent = 'Adgangskoderne stemmer ikke overens.';
            hasError = true;
        }

        if (hasError) return;

        signupButton.disabled = true;
        spinner.classList.remove('hidden');
        signupButton.querySelector('span').textContent = 'Opretter konto...';

        try {
            const response = await fetch('/api/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, phone, password }),
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok) {
                window.location.href = '/auth/login';
            } else {
                const error = data.error || 'Signup mislykkedes. Prøv igen.';
                handleError(error);
            }
        } catch (error) {
            console.error('Signup error:', error);
            generalError.textContent = 'Der opstod en fejl. Prøv venligst igen senere.';
        } finally {
            signupButton.disabled = false;
            spinner.classList.add('hidden');
            signupButton.querySelector('span').textContent = 'Opret konto';
        }
    });

    function handleError(error) {
        const lowerError = error.toLowerCase();
        if (lowerError.includes('email')) {
            emailError.textContent = error;
        } else if (lowerError.includes('phone') || lowerError.includes('telefon')) {
            phoneError.textContent = error;
        } else if (lowerError.includes('password') || lowerError.includes('adgangskode')) {
            passwordError.textContent = error;
        } else if (lowerError.includes('name') || lowerError.includes('navn')) {
            nameError.textContent = error;
        } else {
            generalError.textContent = error;
        }
    }
});