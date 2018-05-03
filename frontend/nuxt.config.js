module.exports = {
    /*
    ** Headers of the page
    */
    head: {
      title: 'EKTotal 4.0',
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { hid: 'description', name: 'description', content: 'EKTotal frontend' }
      ],
      link: [
        { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
      ]
    },
    /*
    ** disable ssr
    */
    mode: 'spa',
    /*
    ** Customize the progress bar color
    */
    loading: { color: '#3B8070' },
    /*
    ** Build configuration
    */
    build: {
      /*
      ** Run ESLint on save
      */
      extend (config, { isDev, isClient }) {
        if (isDev && isClient) {
          config.module.rules.push({
            enforce: 'pre',
            test: /\.(js|vue)$/,
            loader: 'eslint-loader',
            exclude: /(node_modules)/
          })
        }
      },
      vendor: ['vue-clipboard2']
    },
    plugins: [
      '~/plugins/vue-clipboard2'
    ],
    modules: [
      'bootstrap-vue/nuxt',
      'nuxt-fontawesome',
      '@nuxtjs/axios',
      '@nuxtjs/toast'
    ],
    toaat: {
      position: 'top-right',
      iconPack : 'material'
    },
    axios: {
      baseURL: "/"
    },
    fontawesome: {
      imports: [
        {
          set: '@fortawesome/fontawesome-free-regular'
        },
        {
          set: '@fortawesome/fontawesome-free-solid'
        }
      ]
    }
  }
  