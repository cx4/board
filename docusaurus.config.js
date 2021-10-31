// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: '安全测试部',
  tagline: '数据驱动安全',
  url: 'https://secure.yrzdm.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',
  organizationName: 'cnnho', // Usually your GitHub org/user name.
  projectName: 'board', // Usually your repo name.
  themes:['@docusaurus/theme-live-codeblock'],
  plugins:[
  [require.resolve("@easyops-cn/docusaurus-search-local"),
  {
    hashed:true,
    translations:{
      "search_placeholder": "搜索一下",
      "see_all_results": "查看所有结果",
      "no_results": "没有相关内容.",
      "search_results_for": "搜索关键字 \"{{ keyword }}\"",
      "search_the_documentation": "搜索一下安全文档",
      "count_documents_found": "{{ count }} 个文档被找到",
      "count_documents_found_plural": "{{ count }} 个文档被搜索到",
      "no_documents_were_found": "没有找到相关文档"
},
  },],
  ],
  presets: [
    [
      '@docusaurus/preset-classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          editUrl: 'https://github.com/facebook/docusaurus/edit/main/website/',
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          editUrl:
            'https://github.com/facebook/docusaurus/edit/main/website/blog/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:

    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({    
      navbar: {
        title: 'SecureWiki',
        logo: {
          alt: 'SecureWiki',
          src: 'img/logo.svg',
        },
        items: [
          {
            type: 'doc',
            docId: 'intro',
            position: 'left',
            label: '安全文档',
          },
          {to: '/blog', label: 'Blog', position: 'left'},
          {to: '/boardcast', label: '安全资讯看板', position: 'left'},
          {to: '/month/10/report.html', label: '安全月报', position: 'left'},
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: '安全文档',
                to: '/docs/intro',
              },
            ],
          },
          {
            title: '质量平台链接',
            items: [
              {
                label: '质量中心导航',
                href: 'http://www.cnnho.pro',
              },
              {
                label: '安全管理平台',
                href: 'http://safe.cnnho.pro',
              },
              {
                label: '质量中心wiki',
                href: 'http://wiki.cnnho.pro',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              }
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} SecureWiki. Built with Docusaurus.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
};

module.exports = config;
