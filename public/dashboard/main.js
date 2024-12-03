// Enhanced JavaScript for Dark Mode, Profile Menu, Search Functionality, Custom URL Handling, Modern Article Page Navigation, Improved UX, Time-Based Progress Indicator, and API Integration for Tracking Visits and Help Requests

// Dark mode toggle functionality
const darkModeToggle = document.getElementById('darkModeToggle');
const htmlElement = document.documentElement;
const darkModeIcon = document.getElementById('darkModeIcon');

// Toggle dark mode and save preference
const toggleDarkMode = () => {
    const isDark = htmlElement.classList.toggle('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    darkModeIcon.className = isDark ? 'fas fa-moon' : 'fas fa-sun';
    // Send dark mode preference to server
    sendApiData('/api/user-preference', { theme: isDark ? 'dark' : 'light' });
};

darkModeToggle.addEventListener('click', toggleDarkMode);

// Load theme from localStorage on page load
document.addEventListener('DOMContentLoaded', () => {
    const theme = localStorage.getItem('theme');
    if (theme === 'dark') {
        htmlElement.classList.add('dark');
        darkModeIcon.className = 'fas fa-moon';
    }
    // Check if there is a guide in the URL and navigate directly
    const urlParams = new URLSearchParams(window.location.search);
    const guideIndex = urlParams.get('guide');
    if (guideIndex) {
        navigateToGuidePage(parseInt(guideIndex));
    }
    // Send page visit data to server
    sendApiData('/api/visit', { page: window.location.pathname });
});

// Profile menu toggle functionality
const profileMenuToggle = document.getElementById('profileMenuToggle');
const profileMenu = document.getElementById('profileMenu');

profileMenuToggle.addEventListener('click', () => {
    const isExpanded = profileMenuToggle.getAttribute('aria-expanded') === 'true';
    profileMenuToggle.setAttribute('aria-expanded', !isExpanded);
    profileMenu.classList.toggle('hidden');
    // Send profile menu toggle event to server
    sendApiData('/api/profile-menu', { expanded: !isExpanded });
});

// Enhanced Search functionality with improved suggestions and arrow key navigation
const searchInput = document.getElementById('searchInput');
const searchButton = document.getElementById('searchButton');
const searchResults = document.getElementById('searchResults');
const resultsList = document.getElementById('resultsList');
const suggestions = document.getElementById('suggestions');
const suggestionsList = document.getElementById('suggestionsList');

let selectedSuggestionIndex = -1;

const guides = [
    { title: 'Advanced Troubleshooting', description: 'Resolve complex issues with our advanced troubleshooting guide to minimize downtime and maximize efficiency.', content: 'In this comprehensive article, we provide detailed steps and troubleshooting tips for resolving complex issues in your system. Learn how to diagnose problems effectively, avoid common pitfalls, and keep your systems running smoothly.', youtubeId: 'dQw4w9WgXcQ' },
    { title: 'Integrating Third-Party Tools', description: 'Seamlessly integrate third-party tools into your workflow for increased productivity and smarter collaboration.', content: 'This article guides you through the process of integrating popular third-party tools like Slack, Trello, and Zapier into your workflow. Boost your productivity with seamless integration and enhance your team collaboration effortlessly.', youtubeId: 'V-_O7nl0Ii0' },
    { title: 'Customizing Your Dashboard', description: 'Learn how to customize your dashboard to suit your support needs and streamline your daily workflow.', content: 'Discover how to personalize your dashboard step-by-step. This guide covers adding widgets, rearranging components, and setting up custom views to make your daily workflow more efficient and tailored to your specific needs.', youtubeId: 'C0DPdy98e4c' }
];

// Display suggestions as the user types with enhanced UX
const displaySuggestions = (query) => {
    suggestionsList.innerHTML = '';
    const filteredGuides = guides.filter(guide => guide.title.toLowerCase().includes(query) || guide.description.toLowerCase().includes(query));
    selectedSuggestionIndex = -1;

    if (filteredGuides.length > 0) {
        filteredGuides.forEach((guide, index) => {
            const suggestionItem = document.createElement('li');
            suggestionItem.className = 'px-4 py-2 hover:bg-brand-100 dark:hover:bg-brand-700 cursor-pointer rounded-md transition duration-200';
            suggestionItem.innerHTML = `<strong>${guide.title}</strong><br><span class='text-sm text-gray-500 dark:text-gray-400'>${guide.description}</span>`;
            suggestionItem.addEventListener('click', () => {
                searchInput.value = guide.title;
                suggestions.classList.add('hidden');
                navigateToGuidePage(guides.indexOf(guide));
            });
            suggestionsList.appendChild(suggestionItem);
        });
        suggestions.classList.remove('hidden');
    } else {
        suggestions.classList.add('hidden');
    }
};

searchInput.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase().trim();
    if (query) {
        displaySuggestions(query);
    } else {
        suggestions.classList.add('hidden');
    }
});

// Handle search on button click or enter key press
const handleSearch = () => {
    const query = searchInput.value.toLowerCase().trim();
    resultsList.innerHTML = '';

    if (query) {
        const filteredGuides = guides.filter(guide => guide.title.toLowerCase().includes(query) || guide.description.toLowerCase().includes(query));
        if (filteredGuides.length > 0) {
            filteredGuides.forEach(guide => {
                navigateToGuidePage(guides.indexOf(guide));
            });
        } else {
            searchResults.classList.remove('hidden');
            resultsList.innerHTML = `<li class='text-gray-700 dark:text-gray-300'>No results found. Try searching for something else.</li>`;
        }
    }
};

searchButton.addEventListener('click', handleSearch);

// Arrow key navigation for suggestions
searchInput.addEventListener('keydown', (e) => {
    const suggestionItems = suggestionsList.getElementsByTagName('li');
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (selectedSuggestionIndex < suggestionItems.length - 1) {
            selectedSuggestionIndex++;
        }
        updateSuggestionSelection(suggestionItems);
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (selectedSuggestionIndex > 0) {
            selectedSuggestionIndex--;
        }
        updateSuggestionSelection(suggestionItems);
    } else if (e.key === 'Enter') {
        if (selectedSuggestionIndex >= 0 && selectedSuggestionIndex < suggestionItems.length) {
            suggestionItems[selectedSuggestionIndex].click();
        } else {
            handleSearch();
        }
    }
});

const updateSuggestionSelection = (suggestionItems) => {
    Array.from(suggestionItems).forEach((item, index) => {
        if (index === selectedSuggestionIndex) {
            item.classList.add('bg-brand-100', 'dark:bg-brand-700');
        } else {
            item.classList.remove('bg-brand-100', 'dark:bg-brand-700');
        }
    });
};

// Hide suggestions when clicking outside
document.addEventListener('click', (e) => {
    if (!suggestions.contains(e.target) && e.target !== searchInput) {
        suggestions.classList.add('hidden');
    }
});

// Enhanced Guide Page Navigation with Modern UI and Working Share, Save, and Get Help Now Buttons
const navigateToGuidePage = (guideIndex) => {
    const guide = guides[guideIndex];
    // Update the URL with the guide index
    window.history.pushState({}, '', `?guide=${guideIndex}`);

    const guidePage = document.createElement('div');
    guidePage.className = 'fixed inset-0 bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-white overflow-y-auto';

    guidePage.innerHTML = 
        `<main class="max-w-screen-xl mx-auto mt-20 p-6">
            <article class="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8 mb-6">
                <div class="flex flex-col md:flex-row items-start mb-8">
                    <div class="flex-1 md:mr-8">
                        <h1 class="text-5xl font-extrabold mb-4">${guide.title}</h1>
                        <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">Published on April 4, 2023</p>
                        <div class="mb-6">
                            <!-- Removed the first image as per user request -->
                            <img alt="Random image" src="https://random-image-pepebigotes.vercel.app/api/random-image" class="w-full h-auto rounded-lg shadow-md mt-4">
                        </div>
                        <p class="text-lg leading-relaxed mb-6">${guide.content}</p>
                    </div>
                    <div class="w-full md:w-1/3 bg-gray-50 dark:bg-gray-700 p-4 rounded-lg shadow-md">
                        <h3 class="text-xl font-semibold mb-4">Quick Facts</h3>
                        <ul class="list-disc ml-6 mb-6 leading-relaxed text-gray-700 dark:text-gray-300">
                            <li><strong>Complexity:</strong> Moderate</li>
                            <li><strong>Estimated Time:</strong> 30 mins</li>
                            <li><strong>Tools Needed:</strong> Access to Admin Console</li>
                        </ul>
                    </div>
                </div>
                <div class="aspect-w-16 aspect-h-9 mb-8">
                    <iframe class="w-full h-80 rounded-lg shadow-lg" src="https://www.youtube.com/embed/${guide.youtubeId}" frameborder="0" allowfullscreen></iframe>
                </div>
                <section class="text-lg text-gray-700 dark:text-gray-300">
                    <h2 class="text-3xl font-semibold mb-4">Introduction</h2>
                    <p class="mb-6 leading-relaxed">This article provides everything you need to understand and master the topic of ${guide.title}. Below, you'll find detailed instructions, expert tips, and a step-by-step walkthrough to help you achieve your goals.</p>
                    <h2 class="text-3xl font-semibold mb-4">Key Steps</h2>
                    <ol class="list-decimal ml-6 mb-6 leading-relaxed">
                        <li>Identify the issue using our troubleshooting techniques.</li>
                        <li>Follow each step outlined to resolve specific issues.</li>
                        <li>Apply the best practices to maintain system efficiency.</li>
                    </ol>
                    <h2 class="text-3xl font-semibold mb-4">Video Guide</h2>
                    <p class="mb-6 leading-relaxed">For a more visual learning experience, refer to the video above. It will guide you through the process in real-time and provide helpful insights to make it easier to follow along.</p>
                    <h2 class="text-3xl font-semibold mb-4">Conclusion</h2>
                    <p class="leading-relaxed mb-8">We hope this guide helps you understand the key points of ${guide.title} and improves your workflow efficiency. Feel free to revisit the guide or watch the video for further clarification.</p>
                    <div class="flex justify-center">
                        <button class="px-6 py-3 bg-brand-500 hover:bg-brand-600 text-white rounded-lg font-medium shadow-md transition duration-300" onclick="openFeedback()">Provide Feedback</button>
                    </div>
                </section>
            </article>
            <section class="flex justify-between items-center mb-8">
                <div class="flex gap-6 text-gray-600 dark:text-gray-400">
                    <button class="flex items-center space-x-2 hover:text-brand-500" onclick="shareGuide('${guide.title}', '${guide.description}')">
                        <i class="fas fa-share"></i>
                        <span class="font-medium">Share</span>
                    </button>
                    <button class="flex items-center space-x-2 hover:text-brand-500" onclick="saveGuide('${guide.title}')">
                        <i class="fas fa-bookmark"></i>
                        <span class="font-medium">Save</span>
                    </button>
                </div>
                <button class="flex items-center px-6 py-3 bg-brand-500 hover:bg-brand-600 text-white rounded-lg font-medium shadow-md transition duration-300" onclick="openChat()">Get Help Now</button>
            </section>
        </main>`;

    document.body.appendChild(guidePage);
    // Send guide visit data to server
    sendApiData('/api/guide-visit', { guideTitle: guide.title });
};

// Close guide page
const closeGuidePage = () => {
    const guidePage = document.querySelector('.fixed.inset-0');
    if (guidePage) {
        guidePage.remove();
    }
    // Remove the guide parameter from the URL
    window.history.pushState({}, '', window.location.pathname);
};

// Function to handle sharing the guide
const shareGuide = (title, description) => {
    if (navigator.share) {
        navigator.share({
            title: `Check out this guide: ${title}`,
            text: description,
            url: window.location.href
        }).then(() => {
            console.log('Thanks for sharing!');
            // Send share event to server
            sendApiData('/api/guide-share', { guideTitle: title });
        }).catch((error) => {
            console.error('Error sharing:', error);
        });
    } else {
        alert('Your browser does not support the Web Share API. Please copy the link manually.');
    }
};

// Function to handle saving the guide
const saveGuide = (title) => {
    let savedGuides = JSON.parse(localStorage.getItem('savedGuides')) || [];
    if (!savedGuides.includes(title)) {
        savedGuides.push(title);
        localStorage.setItem('savedGuides', JSON.stringify(savedGuides));
        alert(`"${title}" has been saved to your saved guides.`);
        // Send save event to server
        sendApiData('/api/guide-save', { guideTitle: title });
    } else {
        alert(`"${title}" is already in your saved guides.`);
    }
};

// Function to open a chat for help with a modern chat UI
const openChat = () => {
    const chatBox = document.createElement('div');
    chatBox.className = 'fixed bottom-4 right-4 w-96 h-96 bg-white dark:bg-gray-800 rounded-lg shadow-lg flex flex-col overflow-hidden';
    chatBox.innerHTML = 
        `<header class="bg-brand-500 text-white p-4 flex justify-between items-center">
            <h2 class="text-lg font-semibold">Support Chat</h2>
            <button class="text-white" onclick="closeChat()">
                <i class="fas fa-times"></i>
            </button>
        </header>
        <div class="p-4 overflow-y-auto flex-1" id="chatContent">
            <div class="text-gray-700 dark:text-gray-300 mb-2">Hello! How can we assist you today?</div>
        </div>
        <div class="p-4 border-t border-gray-300 dark:border-gray-700 flex items-center">
            <input type="text" id="chatInput" class="w-full p-2 rounded-md dark:bg-gray-700 dark:text-white mr-2" placeholder="Type your message...">
            <button class="bg-brand-500 text-white px-4 py-2 rounded-md" onclick="sendMessage(document.getElementById('chatInput').value)">Send</button>
        </div>`;

    document.body.appendChild(chatBox);
    const chatInput = document.getElementById('chatInput');
    chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            sendMessage(chatInput.value);
            chatInput.value = '';
        }
    });
    // Send chat open event to server
    sendApiData('/api/chat-open', { status: 'opened' });
};

// Function to close the chat
const closeChat = () => {
    const chatBox = document.querySelector('.fixed.bottom-4.right-4');
    if (chatBox) {
        chatBox.remove();
    }
    // Send chat close event to server
    sendApiData('/api/chat-close', { status: 'closed' });
};

// Function to send a message in the chat with modern interaction
const sendMessage = (message) => {
    if (message.trim() !== '') {
        const chatContent = document.getElementById('chatContent');
        const userMessage = document.createElement('div');
        userMessage.className = 'text-right text-brand-500 mb-2';
        userMessage.textContent = message;
        chatContent.appendChild(userMessage);

        // Send message to server
        sendApiData('/api/chat-message', { message: message, sender: 'user' });

        // Simulated bot response with typing indicator
        const botTyping = document.createElement('div');
        botTyping.className = 'text-gray-500 dark:text-gray-400 mb-2 italic';
        botTyping.textContent = 'Support is typing...';
        chatContent.appendChild(botTyping);

        chatContent.scrollTop = chatContent.scrollHeight;

        setTimeout(() => {
            botTyping.remove();
            const botMessage = document.createElement('div');
            botMessage.className = 'text-gray-700 dark:text-gray-300 mb-2';
            botMessage.textContent = 'Thank you for your message. Our support team will get back to you shortly.';
            chatContent.appendChild(botMessage);
            chatContent.scrollTop = chatContent.scrollHeight;

            // Send bot response to server
            sendApiData('/api/chat-message', { message: botMessage.textContent, sender: 'bot' });
        }, 1000);
    }
};

// Function to open a feedback form for the guide
const openFeedback = () => {
    const feedbackBox = document.createElement('div');
    feedbackBox.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center';
    feedbackBox.innerHTML = 
        `<div class="w-full max-w-lg bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
            <h2 class="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Provide Feedback</h2>
            <textarea id="feedbackInput" class="w-full p-3 h-32 rounded-md dark:bg-gray-700 dark:text-white mb-4" placeholder="Let us know your thoughts..."></textarea>
            <div class="flex justify-end gap-4">
                <button class="bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-white px-4 py-2 rounded-md" onclick="closeFeedback()">Cancel</button>
                <button class="bg-brand-500 text-white px-4 py-2 rounded-md" onclick="submitFeedback()">Submit</button>
            </div>
        </div>`;
    document.body.appendChild(feedbackBox);
};

// Function to close the feedback form
const closeFeedback = () => {
    const feedbackBox = document.querySelector('.fixed.inset-0.bg-black.bg-opacity-50');
    if (feedbackBox) {
        feedbackBox.remove();
    }
};

// Function to submit feedback
const submitFeedback = () => {
    const feedbackInput = document.getElementById('feedbackInput').value.trim();
    if (feedbackInput !== '') {
        alert('Thank you for your feedback!');
        closeFeedback();
        // Send feedback to server
        sendApiData('/api/submit-feedback', { feedback: feedbackInput });
    } else {
        alert('Please enter your feedback before submitting.');
    }
};

// Function to send data to the server
const sendApiData = (url, data) => {
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then(response => {
        if (!response.ok) {
            console.error(`Error sending data to ${url}:`, response.statusText);
        }
    }).catch(error => {
        console.error(`Error sending data to ${url}:`, error);
    });
};