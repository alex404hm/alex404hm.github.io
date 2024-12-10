document.addEventListener('DOMContentLoaded', () => {
  const profileSettingsLink = document.querySelector('#profile-settings-link');

  profileSettingsLink?.addEventListener('click', (event) => {
    event.preventDefault();
    createSupportProModal();
  });
});

/**
 * Creates and displays the Support Pro settings modal.
 */
const createSupportProModal = () => {
  const modalTemplate = `
    <div class="modal-overlay fixed inset-0 bg-black bg-opacity-70 flex justify-center items-center z-50">
      <div class="modal-container bg-gray-900 text-white rounded-2xl shadow-2xl w-full max-w-6xl h-4/5 flex">
        <!-- Left Menu -->
        <div class="menu bg-gray-800 w-64 p-6 overflow-y-auto flex flex-col">
          <h2 class="text-xl font-bold mb-6 flex items-center">
            <i class="fas fa-tools text-blue-500 mr-2"></i> Support Pro Indstillinger
          </h2>
          <nav class="space-y-4">
            ${createMenuItem('profile-settings', 'Brugerprofil', 'fa-user-circle')}
            ${createMenuItem('account-settings', 'Konto', 'fa-user-cog')}
            ${createMenuItem('notifications-settings', 'Notifikationer', 'fa-bell')}
            ${createMenuItem('security-settings', 'Sikkerhed', 'fa-shield-alt')}
            ${createMenuItem('theme-settings', 'Tema & Tilpasning', 'fa-paint-brush')}
          </nav>
        </div>
        <!-- Right Content -->
        <div class="content flex-1 p-6 overflow-y-auto">
          ${createContentPanel('profile-settings', 'Brugerprofil', `
            <form id="edit-user-form" class="grid grid-cols-1 md:grid-cols-2 gap-10">
              <!-- Profile Picture Section -->
              <div class="flex flex-col items-center">
                <div class="relative w-48 h-48">
                  <img id="profile-picture-preview" src="https://via.placeholder.com/150" alt="Profile Picture"
                    class="w-full h-full object-cover rounded-full border-4 border-blue-500 shadow-lg">
                  <label for="profile-picture-input" class="absolute bottom-0 right-0 bg-blue-600 text-white p-2 rounded-full cursor-pointer shadow-md hover:bg-blue-700 transition-colors">
                    <i class="fas fa-camera"></i>
                  </label>
                  <input id="profile-picture-input" type="file" accept="image/*" class="hidden">
                </div>
                <button type="button" id="remove-picture" class="text-red-500 mt-4 hover:underline">
                  <i class="fas fa-trash-alt"></i> Fjern billede
                </button>
                <p class="text-gray-400 mt-4 text-center">Upload eller rediger dit profilbillede</p>
              </div>
              <div class="space-y-6">
                ${createInputField('user-username', 'Brugernavn', 'text', 'SupportProBruger', 'AdminUser')}
                ${createInputField('user-email', 'Email', 'email', 'admin@supportpro.com', 'admin@supportpro.com')}
                ${createInputField('user-password', 'Adgangskode', 'password', 'Indtast en ny adgangskode')}
              </div>
              <div class="col-span-2 flex justify-between mt-10">
                <button type="button" id="delete-user" class="bg-red-600 text-white px-6 py-3 rounded-lg shadow-md hover:bg-red-700 transition-colors">
                  <i class="fas fa-user-slash"></i> Slet Konto
                </button>
                <button type="submit" class="bg-blue-600 text-white px-6 py-3 rounded-lg shadow-md hover:bg-blue-700 transition-colors">
                  <i class="fas fa-save"></i> Gem Ændringer
                </button>
              </div>
            </form>
          `, true)}
          ${createContentPanel('account-settings', 'Konto', `
            <p>Administrer dine kontooplysninger her.</p>
          `)}
          ${createContentPanel('notifications-settings', 'Notifikationer', `
            <p>Tilpas dine notifikationsindstillinger her.</p>
          `)}
          ${createContentPanel('security-settings', 'Sikkerhed', `
            <p>Administrer din kontosikkerhed her.</p>
          `)}
          ${createContentPanel('theme-settings', 'Tema & Tilpasning', `
            <div class="space-y-6">
              <div class="flex justify-between items-center">
                <label class="text-gray-400">Tema</label>
                <select id="theme-selector" class="bg-gray-800 text-white rounded-lg px-4 py-2">
                  <option value="system">System</option>
                  <option value="light">Lyst</option>
                  <option value="dark">Mørkt</option>
                </select>
              </div>
              <div class="flex justify-between items-center">
                <label class="text-gray-400">Vis altid kode</label>
                <input type="checkbox" id="show-code-toggle" class="toggle-checkbox">
              </div>
            </div>
          `)}
        </div>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', modalTemplate);
  attachModalEventHandlers();
};

/**
 * Creates a menu item for the left-side menu.
 */
const createMenuItem = (id, label, icon) => `
  <button class="menu-item flex items-center p-3 rounded-lg hover:bg-gray-700 transition-colors" data-target="${id}">
    <i class="fas ${icon} text-blue-500 mr-3"></i> ${label}
  </button>
`;

/**
 * Creates a content panel for the right-side content.
 */
const createContentPanel = (id, title, content, active = false) => `
  <div id="${id}" class="content-panel ${active ? '' : 'hidden'}">
    <h3 class="text-2xl font-bold mb-4">${title}</h3>
    ${content}
  </div>
`;

/**
 * Creates an input field dynamically.
 */
const createInputField = (id, label, type, placeholder, value = '') => `
  <div>
    <label for="${id}" class="block text-sm font-medium text-gray-400 mb-2">${label}</label>
    <input id="${id}" type="${type}" value="${value}" placeholder="${placeholder}" 
      class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors" />
  </div>
`;

/**
 * Attaches event handlers for interactivity.
 */
const attachModalEventHandlers = () => {
  const menuItems = document.querySelectorAll('.menu-item');
  const contentPanels = document.querySelectorAll('.content-panel');

  menuItems.forEach((item) => {
    item.addEventListener('click', () => {
      menuItems.forEach((menuItem) => menuItem.classList.remove('bg-gray-700'));
      contentPanels.forEach((panel) => panel.classList.add('hidden'));

      item.classList.add('bg-gray-700');
      const target = document.querySelector(`#${item.dataset.target}`);
      target.classList.remove('hidden');
    });
  });

  document.querySelector('#profile-picture-input')?.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        document.querySelector('#profile-picture-preview').src = reader.result;
      };
      reader.readAsDataURL(file);
    }
  });

  document.querySelector('#remove-picture')?.addEventListener('click', () => {
    document.querySelector('#profile-picture-preview').src = 'https://via.placeholder.com/150';
  });

  document.querySelector('#theme-selector')?.addEventListener('change', (event) => {
    document.body.className = event.target.value;
  });
};