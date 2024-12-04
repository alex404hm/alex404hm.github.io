document.addEventListener('DOMContentLoaded', () => {
    // Define and cache elements to prevent multiple DOM queries
    const elements = {
        loadingScreen: document.getElementById('loadingScreen'),
        mainContent: document.getElementById('mainContent'),
        themeToggle: document.getElementById('theme-toggle'),
        darkModeIcon: document.getElementById('theme-toggle').querySelector('i'),
        logos: {
            macos: document.getElementById('macos-logo'),
            ios: document.getElementById('ios-logo')
        }
    };

    // Define logo URLs for different themes
    const logoUrls = {
        macos: {
            light: 'https://img.icons8.com/ios-filled/96/ffffff/mac-os.png', // White logo in light mode
            dark: 'https://img.icons8.com/ios-filled/96/ffffff/mac-os.png'  // White logo in dark mode
        },
        ios: {
            light: 'https://img.icons8.com/ios-filled/96/000000/ios-logo.png', // Black logo in light mode
            dark: 'https://img.icons8.com/ios-filled/96/ffffff/ios-logo.png'  // White logo in dark mode
        }
    };

    // Function to hide the loading screen after a short delay and show the main content
    const hideLoadingScreen = () => {
        setTimeout(() => {
            elements.loadingScreen.classList.add('hidden');
            elements.mainContent.classList.remove('hidden');
        }, 2000); // Adjust loading time as needed
    };

    // Function to update theme-related elements (icons, logos)
    const updateThemeElements = (isDark) => {
        // Update dark mode icon
        elements.darkModeIcon.classList.remove('fa-sun', 'fa-moon');
        elements.darkModeIcon.classList.add(isDark ? 'fa-moon' : 'fa-sun');

        // Set the correct logo sources based on the theme
        elements.logos.macos.src = isDark ? logoUrls.macos.dark : logoUrls.macos.light;
        elements.logos.ios.src = isDark ? logoUrls.ios.dark : logoUrls.ios.light;
    };

    // Function to initialize theme based on the saved preference in localStorage
    const initializeTheme = () => {
        const isDark = localStorage.getItem('theme') === 'dark';
        if (isDark) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        updateThemeElements(isDark);
    };

    // Function to toggle theme and update elements
    const toggleTheme = () => {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        updateThemeElements(isDark);
    };

    // Add event listener to the theme toggle button
    if (elements.themeToggle) {
        elements.themeToggle.addEventListener('click', toggleTheme);
    }

    // Show loading screen initially
    if (elements.loadingScreen) {
        elements.loadingScreen.classList.remove('hidden');
    }

    // Initial setup calls
    hideLoadingScreen();
    initializeTheme();
});

// Function to toggle dropdown visibility
function toggleDropdown(element) {
    const dropdownContent = element.querySelector('.dropdown-content');
    if (dropdownContent) {
        dropdownContent.classList.toggle('invisible');
        dropdownContent.classList.toggle('opacity-0');
        dropdownContent.classList.toggle('opacity-100');
    }
}
