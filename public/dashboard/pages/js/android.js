document.addEventListener('DOMContentLoaded', () => {
    // Dark mode setup
    initializeDarkMode();

    // Fetch and display the most popular guides with limit=3
    fetchGuides('/api/guides?category=AndroidOS&limit=3', displayPopularGuides);

    // Search functionality
    initializeSearch();

    // Dark Mode Initialization
    function initializeDarkMode() {
        const theme = localStorage.getItem('theme'); // Get theme from localStorage
        if (theme === 'dark') { // Check if theme is 'dark'
            document.documentElement.classList.add('dark');
            updateThemeIcon('dark');
            updateLogoColors('dark');
        } else if (theme === 'light') { // Check if theme is 'light'
            document.documentElement.classList.remove('dark');
            updateThemeIcon('light');
            updateLogoColors('light');
        } else {
            // If no theme is set, default to light mode
            localStorage.setItem('theme', 'light');
            updateThemeIcon('light');
            updateLogoColors('light');
        }

        document.getElementById('theme-toggle').addEventListener('click', () => {
            if (document.documentElement.classList.toggle('dark')) {
                localStorage.setItem('theme', 'dark'); // Save 'dark' to localStorage
                updateThemeIcon('dark');
                updateLogoColors('dark');
            } else {
                localStorage.setItem('theme', 'light'); // Save 'light' to localStorage
                updateThemeIcon('light');
                updateLogoColors('light');
            }
        });
    }

    function updateThemeIcon(mode) {
        const themeIcon = document.getElementById('theme-icon');
        if (mode === 'dark') {
            themeIcon.classList.replace('fa-sun', 'fa-moon');
            themeIcon.setAttribute('aria-label', 'Switch to light mode');
        } else {
            themeIcon.classList.replace('fa-moon', 'fa-sun');
            themeIcon.setAttribute('aria-label', 'Switch to dark mode');
        }
    }

    function updateLogoColors(mode) {
        const macosIcon = document.getElementById('macos-icon');
        const iosIcon = document.getElementById('ios-icon');
        if (mode === 'dark') {
            macosIcon.src = "https://img.icons8.com/ios-filled/48/ffffff/mac-os.png";
            iosIcon.src = "https://img.icons8.com/ios-filled/48/ffffff/ios-logo.png";
        } else {
            macosIcon.src = "https://img.icons8.com/ios-filled/48/000000/mac-os.png";
            iosIcon.src = "https://img.icons8.com/ios-filled/48/000000/ios-logo.png";
        }
    }

    // Fetch Guides from API
    async function fetchGuides(apiUrl, callback) {
        try {
            const response = await fetch(apiUrl);
            if (!response.ok) throw new Error('Network response was not ok');
            const data = await response.json();
            if (data.guides) {
                callback(data.guides);
            }
        } catch (error) {
            console.error('Error fetching guides:', error);
            displayError('Failed to load guides. Please try again later.');
        }
    }

    // Display Error Message
    function displayError(message) {
        const container = document.getElementById('popularGuidesContainer');
        container.innerHTML = `<p class="text-center text-red-500">${message}</p>`;
    }

    // Display Popular Guides
    function displayPopularGuides(guides) {
        const container = document.getElementById('popularGuidesContainer');
        container.innerHTML = guides.map(createGuideCard).join('');
    }

    // Display Search Results
    function displaySearchResults(guides) {
        const resultsContainer = document.getElementById('resultsContainer');
        if (guides.length === 0) {
            resultsContainer.innerHTML = `<p class="text-center text-gray-500 dark:text-gray-400">No results found for your query.</p>`;
        } else {
            resultsContainer.innerHTML = guides.map(createSearchResultCard).join('');
        }
        toggleVisibility('mostPopularGuides', false);
        toggleVisibility('searchResults', true);
    }

    // Helper to toggle section visibility
    function toggleVisibility(sectionId, visible) {
        document.getElementById(sectionId).classList.toggle('hidden', !visible);
    }

    // Helper function to create a guide card
    function createGuideCard(guide) {
        const { title, summary, subtitle, author, category, publishDate, bannerImage, slug } = guide;
        const imageUrl = bannerImage || 'https://via.placeholder.com/150';
        return `
            <a href="/articles/${encodeURIComponent(category.toLowerCase())}/${encodeURIComponent(slug)}" class="block bg-white dark:bg-darkBlack rounded-2xl shadow-soft p-6 transition-transform duration-300 hover:shadow-hover hover:scale-105 focus:outline-none focus:ring-2 focus:ring-primaryBlue">
                <img src="${imageUrl}" alt="${title} Image" class="w-full h-40 object-cover rounded-lg mb-4">
                <h2 class="text-2xl font-semibold text-gray-800 dark:text-secondaryGray">${title}</h2>
                <p class="text-md font-medium text-gray-700 dark:text-gray-400">${subtitle}</p>
                <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">${summary}</p>
                <div class="mt-4 text-sm text-gray-500 dark:text-gray-400">
                    <p>Author: ${author.name}</p>
                    <p>Published on: ${new Date(publishDate).toLocaleDateString()}</p>
                </div>
            </a>`;
    }

    // Helper function to create a search result card
    function createSearchResultCard(guide) {
        const { title, summary, subtitle, author, category, publishDate, bannerImage, slug } = guide;
        const imageUrl = bannerImage || 'https://via.placeholder.com/150';
        return `
            <a href="/articles/${encodeURIComponent(category.toLowerCase())}/${encodeURIComponent(slug)}" class="block bg-white dark:bg-gray-800 rounded-xl shadow-soft p-6 transition-transform duration-300 hover:shadow-hover hover:scale-105 focus:outline-none focus:ring-2 focus:ring-primaryBlue">
                <div class="flex items-start space-x-4">
                    <img src="${imageUrl}" alt="${title} Image" class="w-32 h-32 rounded-lg object-cover">
                    <div>
                        <h2 class="text-2xl font-semibold text-gray-800 dark:text-secondaryGray">${title}</h2>
                        <p class="text-md font-medium text-gray-700 dark:text-gray-400">${subtitle}</p>
                        <p class="mt-2 text-gray-600 dark:text-gray-400">${summary}</p>
                        <div class="mt-4 text-sm text-gray-500 dark:text-gray-400">
                            <p>Author: ${author.name}</p>
                            <p>Published on: ${new Date(publishDate).toLocaleDateString()}</p>
                        </div>
                    </div>
                </div>
            </a>`;
    }

    // Search Initialization with Debounce and Autocomplete
    function initializeSearch() {
        const searchInput = document.getElementById('searchInput');
        const searchSuggestions = document.getElementById('searchSuggestions');
        let debounceTimeout = null;

        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.trim();
            clearTimeout(debounceTimeout);

            if (query.length === 0) {
                searchSuggestions.classList.add('hidden');
                toggleVisibility('mostPopularGuides', true);
                toggleVisibility('searchResults', false);
                return;
            }

            debounceTimeout = setTimeout(() => {
                fetchGuides(`/api/guides/search?q=${encodeURIComponent(query)}&category=AndroidOS`, (guides) => {
                    displaySuggestions(guides, query);
                });
            }, 300); // 300ms debounce delay
        });

        // Handle clicking outside to close suggestions
        document.addEventListener('click', (e) => {
            if (!searchSuggestions.contains(e.target) && e.target !== searchInput) {
                searchSuggestions.classList.add('hidden');
            }
        });

        // Search Results on Enter Key
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const query = e.target.value.trim();
                if (query.length > 0) {
                    fetchGuides(`/api/guides/search?q=${encodeURIComponent(query)}&category=AndroidOS`, displaySearchResults);
                    searchSuggestions.classList.add('hidden');
                }
            }
        });
    }

    // Display Autocomplete Suggestions
    function displaySuggestions(guides, query) {
        const searchSuggestions = document.getElementById('searchSuggestions');
        if (guides.length === 0) {
            searchSuggestions.innerHTML = `<p class="text-gray-500 dark:text-gray-400 px-4 py-2">No suggestions found.</p>`;
        } else {
            searchSuggestions.innerHTML = guides.map(guide => `
                <a href="/articles/${encodeURIComponent(guide.category.toLowerCase())}/${encodeURIComponent(guide.slug)}" class="block px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md">
                    ${highlightMatch(guide.title, query)}
                </a>
            `).join('');
        }
        searchSuggestions.classList.remove('hidden');
        toggleVisibility('mostPopularGuides', false);
        toggleVisibility('searchResults', true);
    }

    // Highlight Matching Text in Suggestions
    function highlightMatch(text, query) {
        const regex = new RegExp(`(${escapeRegExp(query)})`, 'gi');
        return text.replace(regex, '<span class="bg-yellow-200 dark:bg-yellow-700">$1</span>');
    }

    // Escape RegExp Special Characters
    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
});