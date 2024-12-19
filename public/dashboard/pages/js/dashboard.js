    document.addEventListener('DOMContentLoaded', () => {
        // Cache DOM elements for better performance
        const elements = {
            loadingScreen: document.getElementById('loadingScreen'),
            mainContent: document.getElementById('mainContent'),
            themeToggle: document.getElementById('theme-toggle'),
            themeIcon: document.getElementById('theme-icon'),
            logos: {
                macos: document.getElementById('macos-logo'),
                ios: document.getElementById('ios-logo')
            }
        };

        // Define logo URLs for different themes
        const logoUrls = {
            macos: {
                light: 'https://img.icons8.com/ios-filled/96/000000/mac-os.png', // Black logo in light mode
                dark: 'https://img.icons8.com/ios-filled/96/ffffff/mac-os.png'  // White logo in dark mode
            },
            ios: {
                light: 'https://img.icons8.com/ios-filled/96/000000/ios-logo.png', // Black logo in light mode
                dark: 'https://img.icons8.com/ios-filled/96/ffffff/ios-logo.png'  // White logo in dark mode
            }
        };

        // Function to hide the loading screen and show main content
        const hideLoadingScreen = () => {
            setTimeout(() => {
                if (elements.loadingScreen) {
                    elements.loadingScreen.classList.add('hidden');
                }
                if (elements.mainContent) {
                    elements.mainContent.classList.remove('hidden');
                }
            }, 2000); // Adjust the delay as needed
        };

        // Function to update theme-related elements (icon and logos)
        const updateThemeElements = (isDark) => {
            // Update theme icon
            if (isDark) {
                elements.themeIcon.classList.replace('fa-sun', 'fa-moon');
                elements.themeIcon.setAttribute('aria-label', 'Switch to light mode');
            } else {
                elements.themeIcon.classList.replace('fa-moon', 'fa-sun');
                elements.themeIcon.setAttribute('aria-label', 'Switch to dark mode');
            }

            // Update logos based on theme
            if (elements.logos.macos && elements.logos.ios) {
                elements.logos.macos.src = isDark ? logoUrls.macos.dark : logoUrls.macos.light;
                elements.logos.ios.src = isDark ? logoUrls.ios.dark : logoUrls.ios.light;
            }
        };

        // Function to initialize theme based on localStorage
        const initializeTheme = () => {
            const storedTheme = localStorage.getItem('theme');
            if (storedTheme === 'dark') {
                document.documentElement.classList.add('dark');
                updateThemeElements(true);
            } else {
                document.documentElement.classList.remove('dark');
                updateThemeElements(false);
            }
        };

        // Function to toggle theme
        const toggleTheme = () => {
            const isDark = document.documentElement.classList.toggle('dark');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            updateThemeElements(isDark);
        };

        // Event listener for theme toggle button
        if (elements.themeToggle) {
            elements.themeToggle.addEventListener('click', toggleTheme);
        }

        // Initialize theme and hide loading screen
        initializeTheme();
        hideLoadingScreen();
    });