// Main application class
class App {
    constructor() {
      this.init();
    }
  
    init() {
      document.addEventListener('DOMContentLoaded', () => {
        this.themeManager = new ThemeManager();
        this.slideshow = new Slideshow();
        this.statsManager = new StatsManager();
      });
    }
  }
  
  // Theme Management
  class ThemeManager {
    constructor() {
      this.yearElement = document.getElementById('year');
      this.themeToggleBtn = document.getElementById('theme-toggle');
      this.themeIcon = document.getElementById('theme-icon');
      this.rootEl = document.documentElement;
  
      this.init();
    }
  
    init() {
      this.setCurrentYear();
      this.initializeTheme();
      this.setupEventListeners();
    }
  
    setCurrentYear() {
      if (this.yearElement) {
        this.yearElement.textContent = new Date().getFullYear();
      }
    }
  
    initializeTheme() {
      const isDark = localStorage.getItem('theme') === 'dark' ||
        (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
      this.setTheme(isDark ? 'dark' : 'light');
    }
  
    setTheme(theme) {
      try {
        if (theme === 'dark') {
          this.rootEl.classList.add('dark');
          this.themeIcon?.classList.replace('fa-moon', 'fa-sun');
        } else {
          this.rootEl.classList.remove('dark');
          this.themeIcon?.classList.replace('fa-sun', 'fa-moon');
        }
        localStorage.setItem('theme', theme);
      } catch (error) {
        console.error('Error setting theme:', error);
      }
    }
  
    setupEventListeners() {
      this.themeToggleBtn?.addEventListener('click', () => {
        const newTheme = this.rootEl.classList.contains('dark') ? 'light' : 'dark';
        this.setTheme(newTheme);
      });
    }
  }
  
  // Slideshow Management
  class Slideshow {
    constructor() {
      this.images = [
        'https://images.pexels.com/photos/442150/pexels-photo-442150.jpeg',
        'https://images.pexels.com/photos/845451/pexels-photo-845451.jpeg',
        'https://images.pexels.com/photos/1181354/pexels-photo-1181354.jpeg',
        'https://images.pexels.com/photos/1181341/pexels-photo-1181341.jpeg',
        'https://images.pexels.com/photos/7682087/pexels-photo-7682087.jpeg',
        'https://images.pexels.com/photos/12899151/pexels-photo-12899151.jpeg',
        'https://images.pexels.com/photos/8867427/pexels-photo-8867427.jpeg'
      ];
      this.currentIndex = 0;
      this.intervalDuration = 4000;
      this.bg1 = document.getElementById('bg1');
      this.bg2 = document.getElementById('bg2');
  
      this.init();
    }
  
    init() {
      if (!this.bg1 || !this.bg2) return;
      this.preloadImages();
      this.startSlideshow();
    }
  
    preloadImages() {
      this.images.forEach(src => {
        const img = new Image();
        img.src = src;
      });
    }
  
    startSlideshow() {
      setInterval(() => this.changeSlide(), this.intervalDuration);
    }
  
    changeSlide() {
      this.currentIndex = (this.currentIndex + 1) % this.images.length;
      const nextImage = this.images[this.currentIndex];
  
      if (this.bg1.classList.contains('opacity-100')) {
        this.bg2.style.backgroundImage = `url('${nextImage}')`;
        this.bg1.classList.replace('opacity-100', 'opacity-0');
        this.bg2.classList.replace('opacity-0', 'opacity-100');
      } else {
        this.bg1.style.backgroundImage = `url('${nextImage}')`;
        this.bg2.classList.replace('opacity-100', 'opacity-0');
        this.bg1.classList.replace('opacity-0', 'opacity-100');
      }
    }
  }
  
  // Stats Management
  class StatsManager {
    constructor() {
      this.statsSection = document.getElementById('trustedSection');
      this.statsContainer = document.getElementById('statsContainer');
      this.statsAnimated = false;
      this.API_URL = 'https://api.example.com/stats';
      this.defaultStats = {
        stars: 4670,
        downloads: 80000,
        sponsors: 100
      };
  
      this.init();
    }
  
    init() {
      if (!this.statsSection || !this.statsContainer) return;
      this.setupObserver();
    }
  
    async fetchStats() {
      try {
        const response = await fetch(this.API_URL);
        if (!response.ok) throw new Error('API request failed');
        const data = await response.json();
        return {
          stars: data.stars ?? this.defaultStats.stars,
          downloads: data.downloads ?? this.defaultStats.downloads,
          sponsors: data.sponsors ?? this.defaultStats.sponsors
        };
      } catch (error) {
        console.warn('Failed to fetch stats, using default values:', error);
        return this.defaultStats;
      }
    }
  
    animateNumbers(element, target) {
      if (!element) return;
  
      const duration = 2000; // Animation duration in ms
      const steps = 100;
      const stepDuration = duration / steps;
      let count = 0;
      const increment = Math.ceil(target / steps);
      const suffix = element.getAttribute('data-suffix') || '+';
  
      const interval = setInterval(() => {
        count = Math.min(count + increment, target);
        element.textContent = `${count}${suffix}`;
  
        if (count >= target) {
          clearInterval(interval);
        }
      }, stepDuration);
    }
  
    revealStats(data) {
      const ddElements = this.statsContainer.querySelectorAll('dd[data-key]');
      ddElements.forEach(dd => {
        const key = dd.getAttribute('data-key');
        const value = data[key];
        this.animateNumbers(dd, value);
      });
  
      this.statsContainer.classList.remove('opacity-0', 'scale-95');
      this.statsContainer.classList.add('opacity-100', 'scale-100');
    }
  
    setupObserver() {
      const observer = new IntersectionObserver(async (entries) => {
        if (entries[0].isIntersecting && !this.statsAnimated) {
          this.statsAnimated = true;
          const data = await this.fetchStats();
          this.revealStats(data);
        }
      }, { threshold: 0.3 });
  
      observer.observe(this.statsSection);
    }
  }
  
  // Initialize the application
  const app = new App();