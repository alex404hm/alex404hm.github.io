  // Fetch article data using an API
  const fetchArticleData = async () => {
    try {
      const [,, category, slug] = window.location.pathname.split('/');

      if (!category || !slug) {
        displayAlert('Invalid URL structure. Missing category or slug.');
        return;
      }

      const response = await fetch(`/api/guides/${category}/${slug}`);
      if (!response.ok) throw new Error('Failed to fetch article data.');

      const data = await response.json();
      updatePageContent(data);
    } catch (error) {
      console.error('Error:', error);
      displayAlert('Failed to load article. Please try again later.');
    }
  };

  // Update page content dynamically
  const updatePageContent = (data) => {
    document.title = data.title || 'Modern IT Guide';
    document.querySelector('meta[name="description"]').setAttribute(
      'content',
      data.summary || data.subtitle || ''
    );

    document.getElementById('article-title').textContent = data.title || '';
    document.getElementById('article-subtitle').textContent = data.subtitle || '';
    document.getElementById('header-section').style.backgroundImage = `linear-gradient(rgba(0,0,0,0.6), rgba(0,0,0,0.6)), url('${data.bannerImage || ''}')`;

    document.getElementById('author-name').textContent = data.author?.name || '';
    document.getElementById('author-photo').src = data.author?.photo || 'https://via.placeholder.com/150';
    document.getElementById('publish-date').textContent = data.publishDate || '';

    document.getElementById('article-content').innerHTML = data.content || '';
  };

  // Display alert
  const displayAlert = (message) => {
    const alertBox = document.createElement('div');
    alertBox.className = 'alert';
    alertBox.textContent = message;
    document.body.appendChild(alertBox);
    setTimeout(() => alertBox.remove(), 5000);
  };

  // Set current year
  document.getElementById('year').textContent = new Date().getFullYear();

  // Initialize page
  document.addEventListener('DOMContentLoaded', fetchArticleData);