    document.addEventListener('DOMContentLoaded', () => {
      const API_BASE_URL = 'http://localhost:3000'; // Update this to your actual API base URL

      // DOM Elements
      const themeToggle = document.getElementById('theme-toggle');
      const menuButton = document.getElementById('menu-button');
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('overlay');
      const logoutButton = document.getElementById('logout-button');
      const profileMenuButton = document.getElementById('profile-menu-button');
      const profileDropdown = document.getElementById('profile-dropdown');
      const loader = document.getElementById('loader');
      const ticketsTableBody = document.getElementById('tickets-table-body');
      const recentActivitiesList = document.getElementById('recent-activities-list');
      const totalUsersCount = document.getElementById('total-users-count');
      const openTicketsCount = document.getElementById('open-tickets-count');
      const pendingTicketsCount = document.getElementById('pending-tickets-count');
      const guidesCount = document.getElementById('guides-count');
      const searchInput = document.getElementById('search-input');

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

      // Fetch data from API and update UI
      const fetchData = async () => {
        try {
          const response = await axios.get(`${API_BASE_URL}/api/dashboard-data`, {
            headers: {
              'Authorization': `Bearer ${getToken()}`,
            },
            withCredentials: true,
          });

          const data = response.data;

          // Update Overview Cards
          totalUsersCount.textContent = data.totalUsers;
          openTicketsCount.textContent = data.openTickets;
          pendingTicketsCount.textContent = data.pendingTickets || 0;
          guidesCount.textContent = data.guides;

          // Update Recent Activities
          updateRecentActivities(data.recentActivities);

          // Update Tickets Table
          updateTicketsTable(data.recentTickets);

          // Hide Loader
          loader.classList.add('hidden');
        } catch (error) {
          console.error('Error fetching dashboard data:', error);
          // Display error messages
          totalUsersCount.textContent = 'Error';
          openTicketsCount.textContent = 'Error';
          pendingTicketsCount.textContent = 'Error';
          guidesCount.textContent = 'Error';
          recentActivitiesList.innerHTML = '<li class="text-red-500">Kunne ikke hente seneste aktiviteter. Prøv igen senere.</li>';
          ticketsTableBody.innerHTML = '<tr><td colspan="5" class="py-4 px-6 text-center text-red-500">Kunne ikke hente tickets. Prøv igen senere.</td></tr>';
          // Hide Loader
          loader.classList.add('hidden');
        }
      };

      // Update Recent Activities
      const updateRecentActivities = (activities) => {
        recentActivitiesList.innerHTML = '';
        if (activities && activities.length > 0) {
          activities.forEach(activity => {
            const listItem = document.createElement('li');
            listItem.classList.add('bg-secondaryGray', 'dark:bg-lightBlack', 'p-5', 'rounded-lg', 'shadow-md', 'flex', 'items-center', 'hover:shadow-lg', 'transition-shadow', 'duration-300');
            listItem.innerHTML = `
              <i class="fas fa-user-circle text-primaryBlue text-3xl mr-4" aria-hidden="true"></i>
              <div>
                <p class="text-darkBlack dark:text-white">${sanitizeHTML(activity.description)}</p>
                <p class="text-gray-700 dark:text-gray-300 text-sm">${sanitizeHTML(activity.timestamp)}</p>
              </div>
            `;
            recentActivitiesList.appendChild(listItem);
          });
        } else {
          recentActivitiesList.innerHTML = '<li class="text-secondaryGray">Ingen seneste aktiviteter.</li>';
        }
      };

      // Update Tickets Table
      const updateTicketsTable = (tickets) => {
        ticketsTableBody.innerHTML = '';
        if (tickets && tickets.length > 0) {
          tickets.forEach(ticket => {
            const row = document.createElement('tr');
            row.classList.add('hover:bg-secondaryGray', 'dark:hover:bg-lightBlack', 'transition-colors');
            row.innerHTML = `
              <td class="py-4 px-6 text-sm font-medium text-gray-900 dark:text-white">${sanitizeHTML(ticket.id)}</td>
              <td class="py-4 px-6 text-sm text-gray-700 dark:text-gray-300">${sanitizeHTML(ticket.username)}</td>
              <td class="py-4 px-6 text-sm">
                <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold ${getStatusClasses(ticket.status)}">
                  ${sanitizeHTML(ticket.status)}
                </span>
              </td>
              <td class="py-4 px-6 text-sm text-gray-700 dark:text-gray-300">${formatDate(ticket.createdAt)}</td>
              <td class="py-4 px-6 text-sm">
                <button class="view-ticket-button text-primaryBlue dark:text-accentGreen hover:underline" data-ticket-id="${sanitizeHTML(ticket.id)}">Se</button>
                <!-- Add more action buttons as needed -->
              </td>
            `;
            ticketsTableBody.appendChild(row);
          });
        } else {
          ticketsTableBody.innerHTML = '<tr><td colspan="5" class="py-4 px-6 text-center text-gray-500 dark:text-gray-400">Ingen tickets fundet.</td></tr>';
        }
      };

      // Helper Functions
      const sanitizeHTML = (str) => {
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
      };

      const formatDate = (dateStr) => {
        const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
        return new Date(dateStr).toLocaleDateString('da-DK', options);
      };

      const getStatusClasses = (status) => {
        switch (status.toLowerCase()) {
          case 'åben':
            return 'bg-accentGreen text-white';
          case 'lukket':
            return 'bg-accentRed text-white';
          case 'pending':
            return 'bg-pendingYellow text-white';
          default:
            return 'bg-secondaryGray text-gray-700 dark:text-gray-300';
        }
      };

      // Search Functionality (Optional Enhancement)
      searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const rows = ticketsTableBody.querySelectorAll('tr');

        rows.forEach(row => {
          const cells = row.querySelectorAll('td');
          if (cells.length > 0) {
            const matches = Array.from(cells).some(cell => cell.textContent.toLowerCase().includes(query));
            row.style.display = matches ? '' : 'none';
          }
        });
      });

      // Event Delegation for View Ticket Buttons
      ticketsTableBody.addEventListener('click', (e) => {
        if (e.target && e.target.matches('.view-ticket-button')) {
          const ticketId = e.target.getAttribute('data-ticket-id');
          // Redirect to ticket details page or open a modal
          window.location.href = `/tickets/${ticketId}`;
        }
      });

      // Fetch data on page load
      fetchData();
    });