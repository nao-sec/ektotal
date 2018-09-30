<template>
    <div class="uploadform">
        <div class="toast">
            <h1>EKTotal 4.0</h1>
            <form action="#" method="POST">
                <div class="form-box" v-bind:class="is_focus">
                    <b-form-file 
                    v-model="file" 
                    placeholder=".pcap or .saz file (Max: 30MB)" 
                    @mouseenter.native="file_form_focus = true" 
                    @mouseleave.native="file_form_focus = false"
                    accept=".cap,.pcap,.pcapng,.saz"
                    ></b-form-file>
                </div>
                <b-container>
                    <b-row class="checkbox">
                        <b-col cols="8" @click="toggle">
                            <font-awesome-icon :icon="checkbox" v-bind:class="{accept: is_accept}" class="check" />
                            I accept to the <router-link :to="{name: 'term-of-use'}">Term of Use</router-link>.
                        </b-col>
                        <b-col cols="4">
                            <b-button :disabled="can_submit" :variant="get_submit_button_variant" @click.prevent="upload" class="submit">
                                <span v-if="!is_uploading">Submit</span>
                                <font-awesome-icon v-if="is_uploading" icon="spinner" class="spinner" /> 
                            </b-button>
                        </b-col>
                    </b-row>
                    <b-row class="thanks">
                        <b-col>
                            <h2>SpecialThanks</h2>
                            <p><strong><a href="https://github.com/malwareinfosec/EKFiddle">@EKFiddle</a></strong> We appreciate this great tool!</p>
                        </b-col>
                    </b-row>
                </b-container>
            </form>
        </div>
    </div>
</template>

<script>
import solid from '@fortawesome/fontawesome-free-solid'
import fontawesome from '@fortawesome/fontawesome'

export default {
    data() { 
        return {
            file: null,
            file_form_focus: false,
            is_accept: false,
            is_uploading: false
        };
    },
    computed: {

        is_focus() {
            return {
                focused: Boolean(this.file) || this.file_form_focus
            };
        },
        can_submit() {
            return !Boolean(this.file) || !this.is_accept;
        },
        checkbox() {
            if(this.is_accept) {
                return solid.faCheckSquare;
            } else {
                return solid.faSquare;
            }
        },
        get_submit_button_variant() {
            return Boolean(this.file) && this.is_accept ? 'info' : 'secondary';
        }
    },
    methods: {
        toggle() {
            this.is_accept = !this.is_accept;
        },
        initialize() {
            this.file = null;
            this.file_form_focus = false;
            this.is_accept = false;
        },
        validate() {
            let error = null;
            if(!this.file) {
                error = {
                    message: "You must choose file."
                }
            } else if (this.file.size > 31457280){
                error = {
                    message: "Upload file too lerge."
                }
            } else if (!this.is_accept) {
                error = {
                    message: "You must accept to Term of Use."
                }
            }
            return error;
        },
        async upload() {
            // error check
            let err = this.validate();
            if(err !=  null){
                this.$toast.error(`${fontawesome.icon(solid.faExclamationTriangle).html} ${err.message}`, {duration: 5000});
            }

            // make request
            let form_data = new FormData();
            form_data.append('upfile', this.file);
            let response = await this.$axios.$post('api/submit', form_data, {
                onUploadProgress: e => {
                    this.is_uploading = true;
                }
            }).catch(err => {
                console.error(err);
                this.$toast.error(`${fontawesome.icon(solid.faExclamationTriangle).html} Something error, report me (@nao_sec).`, {duration: 10000});
                this.file = null;
                this.is_uploading = false;
                return;
            });
            this.$router.push({name: 'analyze-id', params: {id: response.id + ".json"}});
        }
    }
}

</script>

<style lang="stylus" scoped>
@import url('https://fonts.googleapis.com/css?family=Yantramanav:700')

logo-color = #2196F3
body-color = gray

.uploadform
    display flex
    justify-content center 
    background-color rgba(0, 0, 0, 0.05)
    height 100vh
    min-height 400px
    
    .toast
        display block
        background-color rgba(255, 255, 255, 0.4)
        width 450px
        height 400px
        margin-top 80px
        h1
            margin 30px           
            font-family 'Yantramanav', sans-serif
            color logo-color
            text-align center
            font-size 80px
            font-weight bold
        .form-box
            padding 20px
        .focused
            border-left solid 6px logo-color
            padding-left 14px
            background-color rgba(255, 255, 255, 0.3)
        .checkbox
            display flex
            align-items center
            color body-color
            font-size 18px
            user-select none
            padding 5px
            .submit
                float right
            .check
                font-size 20px
            .accept
                color logo-color
            .spinner
                animation spin 1.5s linear infinite;
            @keyframes spin 
                0% 
                    transform rotate(0deg)
                100% 
                    transform rotate(360deg)
        .thanks
            font-size 12px
            padding-top 24px
            color body-color
            h2
                font-size 20px
                color logo-color
   
</style>
