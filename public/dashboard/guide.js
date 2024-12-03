// Enhanced sharing functionality
function shareArticle(platform) {
    const url = encodeURIComponent(window.location.href);
    const title = encodeURIComponent(document.getElementById('page-title').innerText);
    
    const shareUrls = {
        facebook: `https://www.facebook.com/sharer/sharer.php?u=${url}`,
        twitter: `https://twitter.com/intent/tweet?url=${url}&text=${title}`,
        linkedin: `https://www.linkedin.com/shareArticle?mini=true&url=${url}&title=${title}`
    };

    if (shareUrls[platform]) {
        window.open(shareUrls[platform], '_blank', 'noopener,noreferrer');
    }
}

// Reading time calculator
function calculateReadingTime() {
    const wordsPerMinute = 200;
    const textContent = document.querySelector('main').innerText;
    const wordCount = textContent.trim().split(/\s+/).length;
    const readingTime = Math.ceil(wordCount / wordsPerMinute);
    document.getElementById('reading-time').innerText = `${readingTime} min read`;
}

document.addEventListener('DOMContentLoaded', () => {
    calculateReadingTime();
    fetchContent();
});

// Fetch content dynamically
async function fetchContent() {
    try {
        const response = await fetch('/api/content');
        const data = await response.json();
        
        document.getElementById('page-title').innerText = data.title;
        document.getElementById('page-description').innerText = data.description;
        document.getElementById('author-name').innerText = data.author.name;
        document.getElementById('author-title').innerText = data.author.title;
        document.getElementById('author-quote').innerText = data.author.quote;
        document.getElementById('publish-date').innerText = data.publishDate;
        document.getElementById('author-image').src = data.author.image;
        document.getElementById('main-content-body').innerHTML = data.mainContent;

        const resourcesContainer = document.getElementById('recommended-resources');
        data.resources.forEach(resource => {
            const resourceElement = document.createElement('div');
            resourceElement.innerHTML = `<a href="${resource.url}" class="text-blue-500 hover:underline">${resource.title}</a>`;
            resourcesContainer.appendChild(resourceElement);
        });

    } catch (error) {
        console.error('Error loading content:', error);
    }
}
