document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = 'http://localhost:3000'; // Replace with your actual API base URL
    let currentGuideId = null;
    let guidesData = [];

    // Elements
    const themeToggle = document.getElementById('theme-toggle');
    const menuButton = document.getElementById('menu-button');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('overlay');
    const createGuideButton = document.getElementById('create-guide-button');
    const guidesTableBody = document.getElementById('guides-table-body');
    const loadingIndicator = document.getElementById('loading-indicator');
    const errorMessage = document.getElementById('error-message');
    const guideModal = document.getElementById('guide-modal');
    const guideForm = document.getElementById('guide-form');
    const modalTitle = document.getElementById('modal-title');
    const cancelButton = document.getElementById('cancel-button');
    const logoutButton = document.getElementById('logout-button');
    const searchInput = document.getElementById('search-input');
    const loader = document.getElementById('loader');

    // Initialize Theme
    const initializeTheme = () => {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.documentElement.classList.add('dark');
        }
    };
    initializeTheme();

    // Theme Toggle
    themeToggle.addEventListener('click', () => {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
    });

    // Sidebar Toggle for Mobile
    const toggleSidebar = () => {
        sidebar.classList.toggle('-translate-x-full');
        overlay.classList.toggle('hidden');
    };

    menuButton.addEventListener('click', toggleSidebar);
    overlay.addEventListener('click', toggleSidebar);

    // Profile Dropdown Toggle
    const profileMenuButton = document.getElementById('profile-menu-button');
    const profileDropdown = document.getElementById('profile-dropdown');

    profileMenuButton.addEventListener('click', (e) => {
        e.stopPropagation(); // Prevent event from bubbling up
        profileDropdown.classList.toggle('hidden');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (event) => {
        if (!profileMenuButton.contains(event.target) && !profileDropdown.contains(event.target)) {
            profileDropdown.classList.add('hidden');
        }
    });

    // Function to get the JWT token from cookies
    const getToken = () => {
        const name = 'token=';
        const decodedCookie = decodeURIComponent(document.cookie);
        const ca = decodedCookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i].trim();
            if (c.indexOf(name) === 0) {
                return c.substring(name.length, c.length);
            }
        }
        return '';
    };

    // Logout Functionality
    const logout = async () => {
        if (!confirm('Er du sikker på, at du vil logge ud?')) return;
        try {
            const response = await fetch(`${API_BASE_URL}/api/logout`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                },
            });
            if (response.ok) {
                window.location.href = '/auth/login';
            } else {
                alert('Kunne ikke logge ud. Prøv igen.');
            }
        } catch (error) {
            console.error('Logout Error:', error);
            alert('Der opstod en fejl under log ud. Prøv igen senere.');
        }
    };

    logoutButton.addEventListener('click', logout);

    // Open Create Guide Modal
    createGuideButton.addEventListener('click', () => {
        currentGuideId = null;
        modalTitle.textContent = 'Opret Ny Guide';
        guideForm.reset();
        openModal();
    });

    // Open and Close Modal Functions
    const openModal = () => guideModal.classList.remove('hidden');
    const closeModal = () => guideModal.classList.add('hidden');
    cancelButton.addEventListener('click', closeModal);

    // Fetch Guides from API
    const fetchGuides = async () => {
        showLoader();
        hideErrorMessage();
        guidesTableBody.innerHTML = '';

        try {
            const response = await fetch(`${API_BASE_URL}/api/guides`, {
                credentials: 'include',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                },
            });
            if (!response.ok) throw new Error('Kunne ikke hente guider.');
            const data = await response.json();
            guidesData = data.guides || [];
            renderGuides(guidesData);
        } catch (error) {
            console.error('Error fetching guides:', error);
            displayErrorMessage('Kunne ikke hente guider. Prøv igen senere.');
        } finally {
            hideLoader();
        }
    };

    // Render Guides
    const renderGuides = (guides) => {
        if (guides.length === 0) {
            guidesTableBody.innerHTML = `
                <tr>
                    <td colspan="5" class="py-4 px-6 text-center text-darkBlack dark:text-white">Ingen guider fundet.</td>
                </tr>
            `;
        } else {
            guidesTableBody.innerHTML = '';
            guides.forEach(guide => appendGuideToTable(guide));
        }
    };

    // Append Guide to Table
    const appendGuideToTable = (guide) => {
        const row = document.createElement('tr');
        row.classList.add('border-b', 'border-gray-200', 'dark:border-gray-700', 'hover:bg-lightBlack', 'hover:bg-opacity-20', 'transition-all', 'duration-200');
        row.innerHTML = `
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide._id)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.title)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.slug)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.subtitle)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.category)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.publishDate)}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${sanitizeHTML(guide.views.toString())}</td>
            <td class="py-4 px-6 text-center">
                <button class="edit-guide-btn text-primaryBlue hover:text-accentGreen mr-2" aria-label="Rediger Guide" data-id="${guide._id}">
                    <i class="fas fa-edit" aria-hidden="true"></i>
                </button>
                <button class="delete-guide-btn text-accentRed hover:text-primaryBlue" aria-label="Slet Guide" data-id="${guide._id}">
                    <i class="fas fa-trash-alt" aria-hidden="true"></i>
                </button>
            </td>
        `;
        guidesTableBody.appendChild(row);

        // Add Event Listeners
        row.querySelector('.edit-guide-btn').addEventListener('click', () => editGuide(guide));
        row.querySelector('.delete-guide-btn').addEventListener('click', () => deleteGuide(guide._id));
    };

    // Edit Guide Function
    const editGuide = (guide) => {
        currentGuideId = guide._id;
        modalTitle.textContent = 'Rediger Guide';
        document.getElementById('guide-title').value = guide.title;
        document.getElementById('guide-subtitle').value = guide.subtitle || '';
        document.getElementById('guide-slug').value = guide.slug || '';
        document.getElementById('guide-content').value = guide.content;
        document.getElementById('guide-category').value = guide.category;
        openModal();
    };

    // Delete Guide Function
    const deleteGuide = async (guideId) => {
        if (!confirm('Er du sikker på, at du vil slette denne guide?')) return;
        try {
            showLoader();
            const response = await fetch(`${API_BASE_URL}/api/guides/id/${guideId}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                },
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Kunne ikke slette guide.');
            }
            fetchGuides();
        } catch (error) {
            alert(`Kunne ikke slette guide: ${error.message}`);
        } finally {
            hideLoader();
        }
    };

    // Guide Form Submission Handler
    guideForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const guideData = {
            title: document.getElementById('guide-title').value.trim(),
            slug: document.getElementById('guide-slug').value.trim(),
            subtitle: document.getElementById('guide-subtitle').value.trim(),
            content: document.getElementById('guide-content').value.trim(),
            category: document.getElementById('guide-category').value,
        };

        try {
            showLoader();
            let response;
            if (currentGuideId) {
                response = await fetch(`${API_BASE_URL}/api/guides/id/${currentGuideId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${getToken()}`,
                    },
                    credentials: 'include',
                    body: JSON.stringify(guideData),
                });
            } else {
                response = await fetch(`${API_BASE_URL}/api/guides`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${getToken()}`,
                    },
                    credentials: 'include',
                    body: JSON.stringify(guideData),
                });
            }

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Kunne ikke gemme guide.');
            }

            fetchGuides();
            closeModal();
        } catch (error) {
            alert(`Kunne ikke gemme guide: ${error.message}`);
        } finally {
            hideLoader();
        }
    });

    // Sanitize HTML to prevent XSS
    const sanitizeHTML = (str) => {
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    };

    // Show and Hide Loader
    const showLoader = () => loader.classList.remove('hidden');
    const hideLoader = () => loader.classList.add('hidden');

    // Display Error Message
    const displayErrorMessage = (message) => {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
    };

    // Hide Error Message
    const hideErrorMessage = () => {
        errorMessage.classList.add('hidden');
    };

    // Search Functionality
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const filteredGuides = guidesData.filter(guide => {
            const title = guide.title.toLowerCase();
            const category = guide.category.toLowerCase();
            return title.includes(searchTerm) || category.includes(searchTerm);
        });
        renderGuides(filteredGuides);
    });

    // Fetch Guides on Page Load
    fetchGuides();
});
