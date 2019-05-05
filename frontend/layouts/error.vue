<template>
  <div class="term">
    <div class="error-toast">
      <h1>Error ;(</h1>
      <p>Oups, happen something strange</p>
      <p>Reason: {{error.message}}</p>
    </div>
  </div>
</template>

<script>
  export default {
    props: ['error']
  }
</script>

<style lang="stylus" scoped>
  @import url('https://fonts.googleapis.com/css?family=Yantramanav:700')

  logo-color = #2196F3
  body-color = gray

  .term
    display flex
    justify-content center
    align-items center
    background-color rgba(0, 0, 0, 0.05)
    height 100vh
    min-height 400px

    .error-toast
      display block
      background-color rgba(255, 255, 255, 0.4)
      width 600px
      color body-color
      padding 20px
      h1
      h2
        margin 30px
        font-family 'Yantramanav', sans-serif
        color logo-color
        text-align center
        font-weight bold
      h1
        font-size 80px
      h2
        font-size 40px

</style>
