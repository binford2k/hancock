$(document).ready(function(){
  $('input.action').click( function() {
    takeAction($(this));
  });
  
  console.log(window.location.pathname);
  
  $('a[href="'+window.location.pathname+'"]').parent().addClass("ui-tabs-selected ui-state-active");
});

function takeAction(button){
  var action   = button.attr("name");
  var certname = button.attr("param");
  
  switch(action) {
    case 'revoke':
      alert('Not implemented');
      break;
    case 'clean':
      alert('Not implemented');
      break;
    case 'sign':
      $.get('/sign/'+certname, function(data) {
        console.log(data);
        var results = jQuery.parseJSON(data);
        if(results.status == 'success') {
          button.prop("name", "revoke");
          button.prop("value", "Revoke");          
        }
        else {
          alert('Could not sign certificate: ' + results.message)
        }
      });
      break;
  }  
}