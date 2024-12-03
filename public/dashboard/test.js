document.addEventListener('DOMContentLoaded', () => {
    const loadingScreen = document.getElementById('loadingScreen');
    const themeToggle = document.getElementById('theme-toggle');
    const darkModeIcon = themeToggle.querySelector('i');
    const macosLogo = document.getElementById('macos-logo');
    const iosLogo = document.getElementById('ios-logo');

    // Remove loading screen after a delay
    const hideLoadingScreen = () => {
        setTimeout(() => {
            loadingScreen.classList.add('hidden');
        }, 1000);
    };

    // Update theme-related elements (logos, icons)
    const updateThemeElements = (isDark) => {
        darkModeIcon.classList.toggle('fa-sun', !isDark);
        darkModeIcon.classList.toggle('fa-moon', isDark);
        macosLogo.src = isDark 
            ? 'https://img.icons8.com/ios-filled/96/ffffff/mac-os.png' 
            : 'https://img.icons8.com/ios-filled/96/000000/mac-os.png';
        iosLogo.src = isDark 
            ? 'https://img.icons8.com/ios-filled/96/ffffff/ios-logo.png' 
            : 'https://img.icons8.com/ios-filled/96/000000/ios-logo.png';
    };

    // Initialize theme based on localStorage
    const initializeTheme = () => {
        const isDark = localStorage.getItem('theme') === 'dark';
        if (isDark) {
            document.documentElement.classList.add('dark');
        }
        updateThemeElements(isDark);
    };

    // Toggle theme and update elements
    const toggleTheme = () => {
        document.documentElement.classList.toggle('dark');
        const isDark = document.documentElement.classList.contains('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        updateThemeElements(isDark);
    };

    // Event listeners
    themeToggle.addEventListener('click', toggleTheme);

    // Initial calls
    hideLoadingScreen();
    initializeTheme();
});
