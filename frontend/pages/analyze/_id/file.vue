<template>
    <div>
        <header>
            <h1>File</h1>
            <span> - Case: {{analysis_result['id']}}</span>
        </header>
        <b-table responsive :items="summary_result" fixed>
            <template slot="virustotal" slot-scope="data">
                <a v-bind:href="data.item['virustotal']" target="_blank">{{data.item['virustotal']}}</a>
            </template>
        </b-table>
    </div>
</template>

<script>
import solid from '@fortawesome/fontawesome-free-solid'

export default {
    computed:{
        analysis_result () {
            return this.$store.state.analyze.scoped_analyze_result;
        },
        summary_result() {
            let results = this.$store.state.analyze.scoped_analyze_result;
            let table_items = [];
            results['data'].forEach(d => {
                if(d['result'] && d['result']['description'] && d['result']['description']['virustotal']){
                    let scope = d['result']['description'];
                    let row = {};
                    row['context'] = d['result']['name'];
                    row['hash'] = scope['sha256'];
                    row['virustotal'] = scope['virustotal']
                    table_items.push(row);
                }
            });
            return table_items;
        }
  }
}
</script>


<style lang="stylus">
h1
    font-size 60px
header
    padding-top 40px
    padding-bottom 40px
    color dimgray
    h1
        color black
.main-summary
    text-align center
    color dimgray
    padding-top 40px
    padding-bottom 40px
    strong 
        color red
table
    overflow-wrap break-word
    word-wrap break-word
</style>
