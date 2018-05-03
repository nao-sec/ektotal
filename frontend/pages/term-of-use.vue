<template>
    <div class="term">
        <div class="toast">
            <h1>About</h1>
            <h2>EKTotal</h2>
            <p>EKTotal is an integrated analysis tool that can automatically analyze the traffic of Drive-by Download attacks. The proposed software package can identify four types of Exploit Kits such as RIG and Magnitude, and more than ten types of attack campaigns such as Seamless and Fobos. EKTotal can also extract exploit codes and malware. The proposed heuristic analysis engine is based on Exploit Kit tracking research conducted since 2017, and is known as team "nao_sec". EKTotal provides a user-friendly web interface and powerful automated analysis functions. Thus, EKTotal can assist SOC operators and CSIRT members and researchers.</p>
            <h2>Term of Use</h2>
            <p>Use this website at your own risk. If you download or use of any information from this website, you assume complete responsibility for any resulting loss or damage. Also, we can access submitted data for the purpose of creating signatures.</p>
            <p><router-link :to="{name: 'index'}">back</router-link></p>
        </div>
    </div>
</template>

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
    
    .toast
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
