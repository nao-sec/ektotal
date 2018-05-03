export const state = () => ({
    analyze_results: [],
    index_dictionary: {},
    scoped_analyze_result: null
});

export const getters = {
    result_length: state => {
        if(state.scoped_analyze_result){
            return state.scoped_analyze_result.data.length;
        }
        return null;
    },
    malicious_result_length: state => {
        if(state.scoped_analyze_result){
            return state.scoped_analyze_result.data.filter(d => d.is_malicious).length;
        }
        return null;
    },
    include_malicious_file_result_length: state => {
        if(state.scoped_analyze_result){
            return state.scoped_analyze_result.data.filter(d => d.result && d.result.description && d.result.description.virustotal).length;
        }
        return null;
    }
}

export const mutations = {
    get_length(state) {
        return state.analyze_results.length;
    },
    get_index(state, id) {
        if(id in state.index_dictionary) {
            return state.index_dictionary[id];
        } else {
            return null;
        }
    },
    push_results(state, data) {
        let error_message = null;
        //check data variable struct
        if(!("id" in data))
            error_message = "\"id\" key not found.";
        if(!("data" in data))
            error_message = "\"data\" key not found.";
        if(error_message){
            throw new TypeError("Analyze data format error: " + error_message);
        }

        const index = (state.analyze_results.push(data)) - 1;

        state.index_dictionary[data['id']] = index;
    },
    get_results(state, id) {
        if(!(id in state.index_dictionary))
            return null;
        return state.analyze_results[state.index_dictionary[id]];
    },
    change_scoped(state, id) {
        let index = mutations.get_index(state, id);
        if(index == null) return false;
        state.scoped_analyze_result = state.analyze_results[index];
        return true;
    }
}

export const actions = {
    async fetch_analyzed_data(context, id) {
        let response = await this.$axios.$get('/api/result/' + this.$route.params.id).catch(err => {
            console.log(err);
            return false;
        });
        context.commit('push_results', response);
        context.commit('change_scoped', response['id']);
        return true;
    }
}