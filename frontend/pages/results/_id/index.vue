<template>
  <div>
    <header>
      <h1>Summary</h1>
      <span> - Case: {{analysis_result['id']}}</span>
    </header>
    <b-container>
      <b-row>
        <b-col class="main-summary">
          <h1><strong>{{$store.getters['analyze/malicious_result_length']}}</strong>/{{$store.getters['analyze/result_length']}}</h1>
          <p>Number of Malicious Traffic</p>
        </b-col>
        <b-col class="main-summary">
          <h1><strong>{{$store.getters['analyze/include_malicious_file_result_length']}}</strong></h1>
          <p>Number of Malicious File</p>
        </b-col>
        <b-col class="main-summary">
          <h1><strong :class="{'green': !is_included_malicious_traffic}"><font-awesome-icon :icon="get_malicious_icon" /></strong></h1>
          <p v-if="is_included_malicious_traffic"><strong>Malicious Traffic</strong></p>
          <p v-if="!is_included_malicious_traffic">Clean Traffic</p>
        </b-col>
      </b-row>
    </b-container>
    <header>
      <h1>Result</h1>
    </header>
    <b-table responsive :items="summary_result" fixed>
      <template slot="CVE_numbers" slot-scope="data">
                <span v-for="cve in data.item['CVE_numbers']" :key="cve">
                    <b-badge variant="danger">{{cve}}</b-badge>
                </span>
      </template>
      <template slot="name" slot-scope="data">
        <span>{{data.item['name']['name']}}</span>
        <span v-if="Boolean(data.item['name']['enc_key'])">
                    <br>
                    <b-badge @mouseleave="init_copy_message" variant="primary" @click="copy(data.item['name']['enc_key'], data.index)" v-bind:id="get_enc_id(data.index)" >Encode Key: {{data.item['name']['enc_key']}} <font-awesome-icon icon="clipboard" /></b-badge>
                    <b-tooltip :target="get_enc_id(data.index)" placement="bottom" delay="{ show:200, hide:0 }">
                        {{ copy_message }}
                    </b-tooltip>
                </span>
      </template>
    </b-table>
  </div>
</template>

<script>
  import { faBug, faCheck } from '@fortawesome/free-solid-svg-icons'

  export default {
    data() {
      return {
        copy_message: "Click to copy"
      }
    },
    computed:{
      analysis_result () {
        return this.$store.state.analyze.scoped_analyze_result;
      },
      get_malicious_icon() {
        if(this.$store.getters['analyze/malicious_result_length'] > 0)
          return faBug;
        return faCheck;
      },
      is_included_malicious_traffic() {
        return this.$store.getters['analyze/malicious_result_length'] > 0;
      },
      summary_result() {
        let results = this.$store.state.analyze.scoped_analyze_result;
        let table_items = [];
        results['data'].forEach(d => {
          let row = {};
          row['name'] = {
            "name": d['result'] ? d['result']['name'] : null,
            "enc_key": d['result'] && d['result']['description'] && d['result']['description']['enc_key'] ?d['result']['description']['enc_key'] : null
          };
          row['URL'] = d['URL'];
          row['CVE_numbers'] = d['result'] && d['result']['description'] && d['result']['description']['cve_numbers'] ? d['result']['description']['cve_numbers'] : [];
          table_items.push(row);
        });
        return table_items;
      }
    },
    methods: {
      get_enc_id(id) {
        return "enc_"+id;
      },
      async copy(text, id) {
        await this.$copyText(text).catch(e => {
          this.copy_message = "AHHH, no copied?! ;(";
          exit();
        });
        this.copy_message = "Copied!";
      },
      init_copy_message() {
        this.copy_message = "Click to copy";
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
    .green
      color green
  table
    overflow-wrap break-word
    word-wrap break-word
</style>
