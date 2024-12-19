// Fetch article data using an API
const fetchArticleData = async () => {
  try {
    const [,, category, slug] = window.location.pathname.split('/');

    if (!category || !slug) {
      console.warn('Category or slug not found in URL.');
      displayAlert('Unable to load the article. Please check the URL.', 'error');
      return;
    }

    const response = await fetch(`/api/guides/${category}/${slug}`);
    if (!response.ok) throw new Error('Failed to fetch article data.');

    const data = await response.json();
    updatePageContent(data);
  } catch (error) {
    console.error('Error fetching article data:', error);
    displayAlert('Unable to load the article. Please try again later.', 'error');
  }
};

// Update page content dynamically
const updatePageContent = (data) => {
  // Update meta tags
  document.title = data.title || 'Article';
  document.querySelector('meta[name="description"]').setAttribute(
    'content',
    data.summary || data.subtitle || 'An insightful guide.'
  );

  // Update header
  document.getElementById('article-title').textContent = data.title || 'Untitled Article';
  document.getElementById('article-subtitle').textContent = data.subtitle || 'No subtitle available.';
  const headerSection = document.getElementById('header-section');
  headerSection.style.backgroundImage = data.bannerImage
    ? `linear-gradient(rgba(0,0,0,0.6), rgba(0,0,0,0.6)), url('${data.bannerImage}')`
    : 'linear-gradient(rgba(0,0,0,0.6), rgba(0,0,0,0.6)), #1e3a8a';

  // Update author details
  if (data.author) {
    document.getElementById('author-photo').src = data.author.photo || 'https://via.placeholder.com/150';
    document.getElementById('author-name').textContent = data.author.name || 'Unknown Author';
    document.getElementById('author-title').textContent = data.author.title || 'No title provided.';
    document.getElementById('author-quote').textContent = data.author.quote || 'No quote available.';
  }

  // Update content and metadata
  document.getElementById('publish-date').textContent = data.publishDate || 'Unknown Date';
  document.getElementById('article-content').innerHTML = data.content || '<p>No content available.</p>';

  calculateReadingTime(data.content || '');
};

// Calculate and display reading time
const calculateReadingTime = (content) => {
  const wordsPerMinute = 200;
  const textContent = content.replace(/<[^>]+>/g, ''); // Remove HTML tags
  const wordCount = textContent.trim().split(/\s+/).length;
  const readingTime = Math.ceil(wordCount / wordsPerMinute);
  document.getElementById('reading-time').textContent = `${readingTime} min read`;
};

// Show alerts with modern UI
const displayAlert = (message, type = 'info') => {
  const alertBox = document.createElement('div');
  alertBox.className = `alert alert-${type}`;
  alertBox.textContent = message;
  document.body.appendChild(alertBox);
  setTimeout(() => alertBox.remove(), 3000);
};

// Save Article
const saveArticle = () => displayAlert('Article saved for later reading!', 'success');

// Share Article
const shareArticle = () => {
  const url = window.location.href;
  if (navigator.share) {
    navigator
      .share({ title: document.title, url })
      .then(() => console.log('Article shared successfully.'))
      .catch(console.error);
  } else {
    prompt('Copy this link to share:', url);
  }
};

// Open chatbot placeholder
const openChatbot = () => displayAlert('Chatbot feature coming soon!', 'info');

// Initialize the page on DOM content loaded
document.addEventListener('DOMContentLoaded', () => {
  fetchArticleData();
  document.getElementById('year').textContent = new Date().getFullYear();

  // Attach event listeners
  document.getElementById('save-article-btn')?.addEventListener('click', saveArticle);
  document.getElementById('share-article-btn')?.addEventListener('click', shareArticle);
  document.querySelector('.chatbot-button')?.addEventListener('click', openChatbot);
});
