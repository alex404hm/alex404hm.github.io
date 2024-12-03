document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = 'http://localhost:3001';
    let currentGuideId = null;

    // Elements
    const elements = {
        themeToggle: document.getElementById('theme-toggle'),
        menuButton: document.getElementById('menu-button'),
        sidebar: document.getElementById('sidebar'),
        createGuideButton: document.getElementById('create-guide-button'),
        guidesTableBody: document.getElementById('guides-table-body'),
        loadingIndicator: document.getElementById('loading-indicator'),
        errorMessage: document.getElementById('error-message'),
        guideModal: document.getElementById('guide-modal'),
        guideForm: document.getElementById('guide-form'),
        modalTitle: document.getElementById('modal-title'),
        cancelButton: document.getElementById('cancel-button'),
    };

    // Initialize Theme
    const initializeTheme = () => {
        const savedTheme = localStorage.getItem('theme');
        document.documentElement.classList.toggle('dark', savedTheme === 'dark');
    };

    // Show/Hide Elements
    const toggleElementVisibility = (element, isVisible) => {
        element.classList.toggle('hidden', !isVisible);
    };

    // Event Listeners
    elements.themeToggle.addEventListener('click', () => {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
    });

    elements.menuButton.addEventListener('click', () => {
        elements.sidebar.classList.toggle('-translate-x-full');
    });

    elements.createGuideButton.addEventListener('click', () => {
        currentGuideId = null;
        elements.modalTitle.textContent = 'Opret Ny Guide';
        elements.guideForm.reset();
        toggleElementVisibility(elements.guideModal, true);
    });

    elements.cancelButton.addEventListener('click', () => {
        toggleElementVisibility(elements.guideModal, false);
    });

    // Fetch Guides from API
    const fetchGuides = async () => {
        toggleElementVisibility(elements.loadingIndicator, true);
        elements.guidesTableBody.innerHTML = '';

        try {
            const response = await fetch(`${API_BASE_URL}/api/guides`);
            if (!response.ok) throw new Error('Kunne ikke hente guider.');

            const { guides } = await response.json();
            if (guides.length === 0) {
                elements.guidesTableBody.innerHTML = `<tr><td colspan="6" class="py-4 px-6 text-center text-gray-500">Ingen guider fundet.</td></tr>`;
            } else {
                guides.forEach(appendGuideToTable);
            }
        } catch (error) {
            displayErrorMessage('Kunne ikke hente guider. Prøv igen senere.');
        } finally {
            toggleElementVisibility(elements.loadingIndicator, false);
        }
    };

    // Append Guide to Table
    const appendGuideToTable = (guide) => {
        const { _id, title, category, views } = guide;

        const row = document.createElement('tr');
        row.classList.add('border-b', 'hover:bg-lightBlack', 'hover:bg-opacity-20', 'transition-all', 'duration-200');
        row.innerHTML = `
            <td class="py-4 px-6 text-darkBlack dark:text-white">${_id}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${title}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${category}</td>
            <td class="py-4 px-6 text-darkBlack dark:text-white">${views}</td>
            <td class="py-4 px-6 text-center">
                <button class="edit-guide-btn text-primaryBlue hover:text-accentGreen mr-2" aria-label="Edit Guide" data-id="${_id}">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="delete-guide-btn text-accentRed hover:text-primaryBlue" aria-label="Delete Guide" data-id="${_id}">
                    <i class="fas fa-trash-alt"></i>
                </button>
            </td>
        `;
        elements.guidesTableBody.appendChild(row);

        row.querySelector('.edit-guide-btn').addEventListener('click', () => editGuide(guide));
        row.querySelector('.delete-guide-btn').addEventListener('click', () => deleteGuide(_id));
    };

    // Edit Guide
    const editGuide = (guide) => {
        currentGuideId = guide._id;
        elements.modalTitle.textContent = 'Rediger Guide';
        
        const { title, subtitle, summary, content, tags, category, bannerImage, author = {} } = guide;

        elements.guideForm['guide-title'].value = title;
        elements.guideForm['guide-subtitle'].value = subtitle || '';
        elements.guideForm['guide-summary'].value = summary || '';
        elements.guideForm['guide-content'].value = content;
        elements.guideForm['guide-tags'].value = tags?.join(', ') || '';
        elements.guideForm['guide-category'].value = category;
        elements.guideForm['guide-banner'].value = bannerImage || '';
        elements.guideForm['author-name'].value = author.name || '';
        elements.guideForm['author-title'].value = author.title || '';
        elements.guideForm['author-photo'].value = author.photo || '';
        elements.guideForm['author-quote'].value = author.quote || '';

        toggleElementVisibility(elements.guideModal, true);
    };

    // Delete Guide
    const deleteGuide = async (guideId) => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/guides/${guideId}`, { method: 'DELETE' });
            if (!response.ok) throw new Error('Kunne ikke slette guiden.');

            await fetchGuides();
        } catch (error) {
            alert(`Kunne ikke slette guiden: ${error.message}`);
        }
    };

    // Display Error Message
    const displayErrorMessage = (message) => {
        elements.errorMessage.textContent = message;
        toggleElementVisibility(elements.errorMessage, true);
    };

    // Submit Guide Form
    elements.guideForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const guideData = {
            title: elements.guideForm['guide-title'].value.trim(),
            subtitle: elements.guideForm['guide-subtitle'].value.trim(),
            summary: elements.guideForm['guide-summary'].value.trim(),
            content: elements.guideForm['guide-content'].value.trim(),
            tags: elements.guideForm['guide-tags'].value.split(',').map(tag => tag.trim()),
            category: elements.guideForm['guide-category'].value,
            bannerImage: elements.guideForm['guide-banner'].value.trim(),
            author: {
                name: elements.guideForm['author-name'].value.trim(),
                title: elements.guideForm['author-title'].value.trim(),
                photo: elements.guideForm['author-photo'].value.trim(),
                quote: elements.guideForm['author-quote'].value.trim()
            },
            publishDate: new Date().toLocaleDateString()
        };

        try {
            const method = currentGuideId ? 'PUT' : 'POST';
            const url = `${API_BASE_URL}/api/guides${currentGuideId ? `/${currentGuideId}` : ''}`;
            const response = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(guideData),
            });

            if (!response.ok) throw new Error(currentGuideId ? 'Kunne ikke opdatere guiden.' : 'Kunne ikke oprette guiden.');

            await fetchGuides();
            toggleElementVisibility(elements.guideModal, false);
        } catch (error) {
            alert(`Kunne ikke gemme guiden: ${error.message}`);
        }
    });

    // Initial Fetch
    fetchGuides();
    initializeTheme();
});
