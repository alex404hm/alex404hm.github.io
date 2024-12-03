document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const themeToggle = document.getElementById('theme-toggle');
    const menuButton = document.getElementById('menu-button');
    const sidebar = document.getElementById('sidebar');
    const createGuideButton = document.getElementById('create-guide-button');
    const guidesTableBody = document.getElementById('guides-table-body');
    const loadingIndicator = document.getElementById('loading-indicator');
    const errorMessage = document.getElementById('error-message');
    const searchInput = document.getElementById('search-input');
    const mainContent = document.querySelector('main');

    const API_BASE_URL = 'http://localhost:3000'; // Replace with your actual API base URL
    let currentGuideId = null;

    // Initialize Theme based on localStorage
    const initializeTheme = () => {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.documentElement.classList.add('dark');
        }
    };

    initializeTheme();

    // Toggle Dark Mode
    themeToggle.addEventListener('click', () => {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
    });

    // Toggle Sidebar for Mobile
    menuButton.addEventListener('click', () => {
        sidebar.classList.toggle('-translate-x-full');
    });

    // Open UI for Creating a New Guide
    createGuideButton.addEventListener('click', () => {
        openGuideEditor('Create New Article');
    });

    // Fetch and Populate Guides
    const fetchGuides = async () => {
        showLoadingIndicator();
        guidesTableBody.innerHTML = '';
        try {
            const response = await fetch(`${API_BASE_URL}/api/guides`, { headers: { 'Content-Type': 'application/json' } });
            if (!response.ok) throw new Error('Could not fetch guides.');

            const { guides } = await response.json();
            if (guides.length === 0) {
                guidesTableBody.innerHTML = `<tr><td colspan="6" class="py-4 px-6 text-center text-gray-500">No guides found.</td></tr>`;
            } else {
                guides.forEach(guide => appendGuideToTable(guide));
            }
        } catch (error) {
            displayErrorMessage('Could not fetch guides. Try again later.');
        } finally {
            hideLoadingIndicator();
        }
    };

    // Helper function to open the guide editor
    const openGuideEditor = (title, guide = null) => {
        mainContent.innerHTML = generateGuideEditorUI(title, guide);
        setupGuideEditorEventListeners(guide);
        currentGuideId = guide ? guide._id : null;
    };

    // Helper function to generate guide editor UI
    const generateGuideEditorUI = (title, guide) => `
        <div class="p-6 bg-white dark:bg-darkBlack rounded-lg shadow-md">
            <h2 class="text-3xl font-bold mb-6 text-darkBlack dark:text-white">${title}</h2>
            <form id="article-form">
                ${generateGuideFormFields(guide)}
                <div class="flex justify-end gap-4">
                    <button type="button" id="full-preview-button" class="px-6 py-3 bg-indigo-600 text-white rounded-lg shadow-md hover:bg-indigo-700 transition-all focus:outline-none">Full Web Preview</button>
                    <button type="button" id="cancel-button" class="px-6 py-3 bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white rounded-lg shadow-md hover:bg-hoverBlue hover:text-white transition-all focus:outline-none">Cancel</button>
                    <button type="submit" id="save-button" class="px-6 py-3 bg-primaryBlue text-white rounded-lg shadow-md hover:bg-hoverBlue transition-all focus:outline-none">Save Guide</button>
                </div>
            </form>
        </div>
    `;

    // Helper function to generate form fields
    const generateGuideFormFields = (guide) => `
        <div class="mb-4">
            <label for="article-title" class="block text-sm font-medium mb-1 text-darkBlack dark:text-white">Title</label>
            <input type="text" id="article-title" value="${guide ? sanitizeHTML(guide.title) : ''}" class="w-full px-4 py-3 rounded-lg bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white focus:ring-2 focus:ring-primaryBlue focus:outline-none" required>
        </div>
        <div class="mb-4">
            <label for="article-category" class="block text-sm font-medium mb-1 text-darkBlack dark:text-white">Category</label>
            <select id="article-category" class="w-full px-4 py-3 rounded-lg bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white focus:ring-2 focus:ring-primaryBlue focus:outline-none" required>
                ${['Windows', 'macOS', 'Linux', 'iOS/iPadOS', 'AndroidOS', 'ChromeOS'].map(category => `
                    <option value="${category}" ${guide && guide.category === category ? 'selected' : ''}>${category}</option>
                `).join('')}
            </select>
        </div>
        <div class="mb-4">
            <label for="article-banner" class="block text-sm font-medium mb-1 text-darkBlack dark:text-white">Banner (Upload or URL)</label>
            <input type="text" id="article-banner" value="${guide ? sanitizeHTML(guide.banner) : ''}" class="w-full px-4 py-3 rounded-lg bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white focus:ring-2 focus:ring-primaryBlue focus:outline-none">
        </div>
        <div class="mb-4">
            <label for="article-tags" class="block text-sm font-medium mb-1 text-darkBlack dark:text-white">Tags</label>
            <input type="text" id="article-tags" value="${guide ? sanitizeHTML(guide.tags) : ''}" class="w-full px-4 py-3 rounded-lg bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white focus:ring-2 focus:ring-primaryBlue focus:outline-none">
        </div>
        <div class="mb-4">
            <label for="youtube-link" class="block text-sm font-medium mb-1 text-darkBlack dark:text-white">YouTube Video Embed Link</label>
            <input type="text" id="youtube-link" value="${guide ? sanitizeHTML(guide.youtubeLink) : ''}" class="w-full px-4 py-3 rounded-lg bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white focus:ring-2 focus:ring-primaryBlue focus:outline-none">
        </div>
        <div class="mb-6">
            <label for="article-content" class="block text-sm font-medium mb-1 text-darkBlack dark:text-white">Content</label>
            <textarea id="article-content" rows="10" class="w-full px-4 py-3 rounded-lg bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white focus:ring-2 focus:ring-primaryBlue focus:outline-none" required>${guide ? sanitizeHTML(guide.content) : ''}</textarea>
        </div>
    `;

    // Setup guide editor event listeners
    const setupGuideEditorEventListeners = (guide) => {
        const articleForm = document.getElementById('article-form');
        const cancelButton = document.getElementById('cancel-button');
        const fullPreviewButton = document.getElementById('full-preview-button');

        articleForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const guideData = collectGuideData();
            if (guide) await updateGuide(currentGuideId, guideData);
            else await createGuide(guideData);
        });

        cancelButton.addEventListener('click', fetchGuides);

        fullPreviewButton.addEventListener('click', renderFullPreview);
    };

    // Collect form data into an object
    const collectGuideData = () => ({
        title: document.getElementById('article-title').value.trim(),
        category: document.getElementById('article-category').value,
        banner: document.getElementById('article-banner').value.trim(),
        tags: document.getElementById('article-tags').value.trim(),
        content: document.getElementById('article-content').value.trim(),
        youtubeLink: document.getElementById('youtube-link').value.trim(),
    });

    // Render full preview of guide
    const renderFullPreview = () => {
        mainContent.innerHTML = `
            <div class="p-10 bg-gray-100 dark:bg-gray-800 rounded-lg shadow-2xl mt-20 max-w-5xl mx-auto">
                <h2 class="text-5xl font-bold mb-10 text-darkBlack dark:text-white text-center">${sanitizeHTML(document.getElementById('article-title').value || 'Title will be displayed here')}</h2>
                <div id="preview-banner-full">${document.getElementById('article-banner').value ? `<img src="${sanitizeHTML(document.getElementById('article-banner').value)}" alt="Banner" class="w-full h-96 object-cover rounded-lg mb-10">` : ''}</div>
                <div id="preview-category-full" class="text-lg font-semibold text-primaryBlue mb-6">${sanitizeHTML(document.getElementById('article-category').value || 'Category will be displayed here')}</div>
                <div id="preview-tags-full" class="text-sm text-gray-600 dark:text-gray-400 mb-8">${sanitizeHTML(document.getElementById('article-tags').value || 'Tags will be displayed here')}</div>
                <div id="preview-youtube-full" class="mb-8">${document.getElementById('youtube-link').value ? `<iframe class="w-full h-96 rounded-lg shadow-lg" src="${sanitizeHTML(document.getElementById('youtube-link').value)}" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>` : ''}</div>
                <div id="preview-content-full" class="text-lg text-darkBlack dark:text-white leading-relaxed">${sanitizeHTML(document.getElementById('article-content').value || 'Content will be displayed here')}</div>
                <div class="flex justify-end mt-10">
                    <button onclick="fetchGuides()" class="px-6 py-3 bg-secondaryGray dark:bg-lightBlack text-darkBlack dark:text-white rounded-lg shadow-md hover:bg-hoverBlue hover:text-white transition-all focus:outline-none">Back to Editor</button>
                </div>
            </div>
        `;
    };

    // Append guide to the table
    const appendGuideToTable = (guide) => {
        const row = document.createElement('tr');
        row.classList.add('border-b', 'border-gray-200', 'dark:border-gray-700', 'hover:bg-lightBlack', 'hover:bg-opacity-20', 'transition-all', 'duration-200');
        row.innerHTML = `
            <td class="py-4 px-6 text-darkBlack dark:text-white">#${guide._id}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.title)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.category)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">Active</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">0</td>
            <td class="py-4 px-6 text-center">
                <button class="edit-guide-btn text-primaryBlue hover:text-accentGreen mr-2" aria-label="Edit Guide" data-id="${guide._id}">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="delete-guide-btn text-accentRed hover:text-primaryBlue" aria-label="Delete Guide" data-id="${guide._id}">
                    <i class="fas fa-trash-alt"></i>
                </button>
            </td>
        `;
        guidesTableBody.appendChild(row);

        // Add event listeners for edit and delete
        row.querySelector('.edit-guide-btn').addEventListener('click', () => openGuideEditor('Edit Guide', guide));
        row.querySelector('.delete-guide-btn').addEventListener('click', () => deleteGuide(guide._id));
    };

    // Display loading indicator
    const showLoadingIndicator = () => loadingIndicator.classList.remove('hidden');
    const hideLoadingIndicator = () => loadingIndicator.classList.add('hidden');

    // Display error message
    const displayErrorMessage = (message) => {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
    };

    // Create Guide
    const createGuide = async (guideData) => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/guides`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(guideData),
            });
            if (!response.ok) throw new Error('Failed to create guide.');
            fetchGuides();
        } catch (error) {
            alert(`Could not create guide: ${error.message}`);
        }
    };

    // Update Guide
    const updateGuide = async (guideId, guideData) => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/guides/${guideId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(guideData),
            });
            if (!response.ok) throw new Error('Failed to update guide.');
            fetchGuides();
        } catch (error) {
            alert(`Could not update guide: ${error.message}`);
        }
    };

    // Delete Guide
    const deleteGuide = async (guideId) => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/guides/${guideId}`, { method: 'DELETE' });
            if (!response.ok) throw new Error('Failed to delete guide.');
            fetchGuides();
        } catch (error) {
            alert(`Could not delete guide: ${error.message}`);
        }
    };

    // Sanitize HTML input to prevent XSS attacks
    const sanitizeHTML = (str) => {
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    };

    // Search functionality
    searchInput.addEventListener('input', () => {
        const filterText = searchInput.value.toLowerCase();
        Array.from(guidesTableBody.getElementsByTagName('tr')).forEach(row => {
            const titleText = row.cells[1].textContent.toLowerCase();
            const categoryText = row.cells[2].textContent.toLowerCase();
            row.style.display = (titleText.includes(filterText) || categoryText.includes(filterText)) ? '' : 'none';
        });
    });

    // Initial Fetch Guides
    fetchGuides();
});
