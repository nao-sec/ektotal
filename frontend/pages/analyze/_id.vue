<template>
    <div class="content-container">
        <b-navbar toggleable="md" type="dark" class="nav">
            <b-navbar-brand :to="{name: 'index'}" class="brand">EKTotal 4.0</b-navbar-brand>

            <b-collapse is-nav id="nav_collapse" class="menu-body">

                <b-navbar-nav>
                <b-nav-item :to="{ name:'analyze-id', params:{ id: $store.state.analyze.scoped_analyze_result.id + '.json' } }" class="link-item" :class="{ 'now-viewing': viewing('analyze-id')}"><font-awesome-icon icon="tachometer-alt" /> Summary</b-nav-item>
                <b-nav-item :to="{ name:'analyze-id-file', params:{ id: $store.state.analyze.scoped_analyze_result.id + '.json' } }" class="link-item" :class="{ 'now-viewing': viewing('analyze-id-file')}"><font-awesome-icon icon="file" /> File</b-nav-item>
                </b-navbar-nav>

                <b-navbar-nav class="ml-auto">

                <b-nav-item right :to="{ name: 'index' }" class="upload-link"><font-awesome-icon icon="upload" /> Upload another file</b-nav-item>
                </b-navbar-nav>

            </b-collapse>
        </b-navbar>
        <div id="inner-content">
            <div class="inner">
                <router-view></router-view>
            </div>
        </div>
    </div>
</template>

<script>

export default {
    validate({ params }){
        return /[a-f0-9\-]+_[a-f0-9\-]+\.json/.test(params.id);
    },
    async fetch({ store, params }){
        let d = await store.$axios.$get('/api/result/' + params.id).catch(e => {
                let err =  new Error("Parameter id not found");
                err.status_code = 404;
                throw err;
        });
        store.commit('analyze/push_results', d);
        store.commit('analyze/change_scoped', d['id']);
    },
    computed: {
        viewing() {
            return (name) => name===this.$route.name;
        }
    }
}
</script>


<style lang="stylus" scoped>
logo-color = #2196F3
body-color = gray
nav-size = 18px

.nav
    background-color logo-color
    font-size nav-size
    height 50px
    padding-top 0
    padding-bottom 0
    min-width 1200px
    .brand
        font-size nav-size
        padding-left calc((100vw - 1200px)/2)
    .upload-link
        padding-right calc((100vw - 1200px)/2)
    .link-item
        display flex
        align-items center
        margin-left 5px
        margin-right 5px
    .now-viewing
        background-color black
        height 50px
    .menu-body
        margin 0
#inner-content
    display flex
    justify-content center
    padding-top 15px
    padding-bottom 15px
    min-width 1200px
    .inner
        min-width 1200px
        max-width 1200px
        padding-top 30px
        padding-bottom 30px
        padding-left 20px
        padding-right 20px
        background-color rgba(255, 255, 255, 0.4)
        border-bottom solid 5px rgb(168, 198, 221)

</style>
