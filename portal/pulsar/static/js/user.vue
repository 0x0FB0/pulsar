<template>
<div id="app">
    <div class="container py-4">
        <div class="row">
            <div class="col-lg-12">
                <div class="card">
                    <div class="card-header">User Details</div>
                    <div class="card-body">
                    <!-- <b-table :items="[app.user_data]"
                     :fields="Object.keys(app.user_data)" caption-top> -->
                    <table class="table">
                      <tbody>
                        <tr v-for="key in Object.keys(app.user_data)">
                          <td><strong>{{app.userFields[key]}}</strong></td>
                          <td v-if="key === 'created_date' && key === 'last_login'">
                          {{new Date(app.user_data[key]).toGMTString()}}
                          </td>
                          <td v-else-if="key === 'is_superuser'">
                          <input v-if="app.user_data[key] === true"
                            type="checkbox" aria-label="Is SuperUser" checked disabled>
                          <input v-else type="checkbox" aria-label="Is SuperUser" disabled>
                          </td>
                          <td v-else-if="key === 'token'">
                          <div class="input-group">
                          <input type="text" :value="app.user_data[key]"
                            id="token" class="form-control" readonly >
                          <a class="pt-2 mx-2 btn btn-sm btn-secondary" @click="copyToken()"><i class="fas fa-copy"></i></a>
                          </div>
                          </td>
                          <td v-else>
                          {{app.user_data[key]}}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                    </div>
                </div>
                <button role="button" class="btn btn-secondary my-2 float-right mr-2"
                    @click="window.location.replace('/accounts/logout/')">
                    <i class="fas fa-door-open"></i>
                     Logout
                </button>
                <button role="button" class="btn btn-secondary my-2 float-right mr-2"
                    @click="window.open('/admin/doc/', '_blank')">
                    <i class="fas fa-external-link-alt"></i>
                     Documentation
                </button>
                <button role="button" class="btn btn-secondary my-2 float-right mr-2"
                    @click="window.open('/admin/', '_blank')">
                    <i class="fas fa-external-link-alt"></i>
                     Admin Panel
                </button>
                <button role="button" class="btn btn-secondary my-2 float-right mr-2"
                    @click="window.open('/pulsar/api/v1/', '_blank')">
                    <i class="fas fa-external-link-alt"></i>
                     API
                </button>
            </div>
        </div>
    </div>
</div>
</template>
<script>
module.exports = {
    methods: {
        copyToken: function(){
        var tok = document.getElementById("token");
        tok.select();
        tok.setSelectionRange(0, 99999);
        document.execCommand("copy");
        }
    },
    mounted: function (){
        app.retrieveToken();
    }
}
</script>