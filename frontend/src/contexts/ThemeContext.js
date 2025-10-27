import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext();

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(() => {
    // Load theme from localStorage or default to 'light'
    try {
      return localStorage.getItem('app_theme') || 'light';
    } catch (error) {
      return 'light';
    }
  });

  const [isDarkMode, setIsDarkMode] = useState(() => theme === 'dark');

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    setIsDarkMode(newTheme === 'dark');
    
    try {
      localStorage.setItem('app_theme', newTheme);
    } catch (error) {
      console.error('Error saving theme to localStorage:', error);
    }
  };

  const setThemeMode = (newTheme) => {
    setTheme(newTheme);
    setIsDarkMode(newTheme === 'dark');
    
    try {
      localStorage.setItem('app_theme', newTheme);
    } catch (error) {
      console.error('Error saving theme to localStorage:', error);
    }
  };

  // Update isDarkMode when theme changes
  useEffect(() => {
    setIsDarkMode(theme === 'dark');
  }, [theme]);

  const value = {
    theme,
    isDarkMode,
    toggleTheme,
    setThemeMode
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}; 