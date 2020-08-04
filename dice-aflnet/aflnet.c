#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <graphviz/gvc.h>

#include "alloc-inl.h"
#include "aflnet.h"

// Protocol-specific functions for extracting requests and responses

region_t* extract_requests_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[4] = {0x0D, 0x0A, 0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int first_token_size = 0;

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) { 
    
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last four bytes are 0x0D0A0D0A
    if ((mem_count > 3) && (memcmp(&mem[mem_count - 3], terminator, 4) == 0)) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      // take the first token (the first word delimited by a space) in the region

      if (cur_end - cur_start > 0) {
      	  int region_size = cur_end - cur_start;
		  first_token_size = index_of(&buf[cur_start], region_size , " ");
		  if (first_token_size < 0 || first_token_size >= region_size || first_token_size > 15) first_token_size = 0; // allocate enough for the null terminator
		  regions[region_count - 1].command = (char *)ck_alloc(first_token_size + 1);
		  memcpy(regions[region_count - 1].command, &buf[cur_start], first_token_size);
      } else {
    	  regions[region_count -1].command = NULL;
      }

      mem_count = 0;  
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++; 
      cur_end++;  

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        // take the first token (the first word delimited by a space) in the region
        if (cur_end - cur_start > 0) {
        	int region_size = cur_end - cur_start;
			first_token_size = index_of(&buf[cur_start], region_size, " ");
			if (first_token_size < 0 || first_token_size >= region_size || first_token_size > 15) first_token_size = 0;
			regions[region_count - 1].command = (char *)ck_alloc(first_token_size + 1);
			memcpy(regions[region_count - 1].command, &buf[cur_start], first_token_size );
        } else {
        	regions[region_count - 1].command = NULL;
        }
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken 
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    regions[0].command = NULL;

    region_count = 1;
  }
  
  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_ftp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
   char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int first_token_size = 0;

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) { 
    
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last two bytes are 0x0D0A
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      // take the first token (the first word delimited by a space) in the region
	   if (cur_end - cur_start > 0) {
		   int region_size = cur_end - cur_start;
		   first_token_size = index_of(&buf[cur_start], region_size, " ");
		   if (first_token_size < 0 || first_token_size >= region_size - 1 || first_token_size > 15) first_token_size = 0; // allocate enough for the null terminator

		   if (first_token_size == 0 && region_size < 6) first_token_size = region_size - 1; // actually, if the entire request is short enough, just take the entire message and treat it as a command

		   regions[region_count - 1].command = (char *)ck_alloc(first_token_size + 1);
		   memcpy(regions[region_count - 1].command, &buf[cur_start], first_token_size );

	   } else {
		   regions[region_count - 1].command = NULL;
	   }
        
      mem_count = 0;  
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++; 
      cur_end++;  

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        // take the first token (the first word delimited by a space) in the region
		if (buf_size > 0) {
			int region_size = cur_end - cur_start;
			first_token_size = index_of(&buf[cur_start], region_size, " ");
			 if (first_token_size < 0 || first_token_size >= region_size || first_token_size > 15)  first_token_size = 0;

			  if (first_token_size == 0 && region_size < 6) first_token_size = region_size - 1;

     		 regions[region_count - 1].command = (char *)ck_alloc(first_token_size + 1);
		     memcpy(regions[region_count - 1].command, &buf[cur_start], first_token_size );

		} else {
			regions[region_count - 1].command = NULL;
		}

        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken 
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    regions[0].command = NULL; // it's possible that we don't have any command anymore.


    region_count = 1;
  }
  
  *region_count_ref = region_count;
  return regions;
}

static unsigned char dtls12_version[2] = {0xFE, 0xFD};

// (D)TLS known and custom constants

// the known 1-byte (D)TLS content types
#define CCS_CONTENT_TYPE 0x14
#define ALERT_CONTENT_TYPE 0x15
#define HS_CONTENT_TYPE 0x16
#define APPLICATION_CONTENT_TYPE 0x17
#define HEARTBEAT_CONTENT_TYPE 0x18

// custom content types
#define UNKNOWN_CONTENT_TYPE 0xFF // the content type is unrecognized

// custom handshake types (for handshake content)
#define UNKNOWN_MESSAGE_TYPE 0xFF // when the message type cannot be determined because the message is likely encrypted
#define MALFORMED_MESSAGE_TYPE 0xFE // when message type cannot be determined because the message appears to be malformed

region_t *extract_requests_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref) {
  unsigned int byte_count = 0;
  unsigned int region_count = 0;
  region_t *regions = NULL;

  unsigned int cur_start = 0;

   while (byte_count < buf_size) { 

     //Check if the first three bytes are <valid_content_type><dtls-1.2>
     if ((byte_count > 3 && buf_size - byte_count > 1) && 
     (buf[byte_count] >= CCS_CONTENT_TYPE && buf[byte_count] <= HEARTBEAT_CONTENT_TYPE)  && 
     (memcmp(&buf[byte_count+1], dtls12_version, 2) == 0)) {
       region_count++;
       regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
       regions[region_count - 1].start_byte = cur_start;
       regions[region_count - 1].end_byte = byte_count-1;
       regions[region_count - 1].state_sequence = NULL;
       regions[region_count - 1].state_count = 0;

       regions[region_count - 1].command = NULL;
       cur_start = byte_count;
     } else { 

      //Check if the last byte has been reached
      if (byte_count == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = byte_count;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        regions[region_count - 1].command = NULL;
        break;
      }
     }

     byte_count ++;
  }

  //in case region_count equals zero, it means that the structure of the buffer is broken 
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;
    regions[0].command = NULL;


    region_count = 1;
  }
  
  *region_count_ref = region_count;
  return regions;
}

// a status code comprises <content_type, message_type> tuples
// message_type varies depending on content_type (e.g. for handshake content, message_type is the handshake message type...)
// 
unsigned int* extract_response_codes_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) 
{
  unsigned int byte_count = 0;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  unsigned int status_code = 0;

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0; // initial status code is 0

  while (byte_count < buf_size) {
    // a DTLS 1.2 record has a 13 bytes header, followed by the contained message
    if ( (buf_size - byte_count > 13) &&
    (buf[byte_count] >= CCS_CONTENT_TYPE && buf[byte_count] <= HEARTBEAT_CONTENT_TYPE)  && 
    (memcmp(&buf[byte_count+1], dtls12_version, 2) == 0)) {
      unsigned char content_type = buf[byte_count];
      unsigned char message_type;
      u32 record_length = read_bytes_to_uint32(buf, byte_count+11, 2);
      
      // the record length exceeds buffer boundaries (not expected)
      if (buf_size - byte_count - 13 - record_length < 0) {
        message_type = MALFORMED_MESSAGE_TYPE;
      }
      else {
        switch(content_type) {
          case HS_CONTENT_TYPE: ;
            unsigned char hs_msg_type = buf[byte_count+13];
            // the minimum size of a correct DTLS 1.2 handshake message is 12 bytes comprising fragment header fields
            if (record_length >= 12) {
              u32 frag_length = read_bytes_to_uint32(buf, byte_count+22, 3);
              // we can check if the handshake record is encrypted by subtracting fragment length from record length 
              // which should yield 12 if the fragment is not encrypted
              // the likelyhood for an encrypted fragment to satisfy this condition is very small 
              if (record_length - frag_length == 12) {
                // not encrypted
                message_type = hs_msg_type;
              } else {
                // encrypted handshake message
                message_type = UNKNOWN_MESSAGE_TYPE;
              }
            } else {
                // malformed handshake message
                message_type = MALFORMED_MESSAGE_TYPE;
            }
          break;
          case CCS_CONTENT_TYPE:
            if (record_length == 1) {
              // unencrypted CCS
              unsigned char ccs_msg_type = buf[byte_count+13];
              message_type = ccs_msg_type;
            } else {
              if (record_length > 1) {
                // encrypted CCS
                message_type = UNKNOWN_MESSAGE_TYPE;
              } else {
                // malformed CCS
                message_type = MALFORMED_MESSAGE_TYPE;
              }
            }
          break;
          case ALERT_CONTENT_TYPE:
            if (record_length == 2) {
              // unencrypted alert, the type is sufficient for determining which alert occurred
              // unsigned char level = buf[byte_count+13];
              unsigned char type = buf[byte_count+14];
              message_type = type;
            } else {
              if (record_length > 2) {
                // encrypted alert
                message_type = UNKNOWN_MESSAGE_TYPE;
              } else {
                // malformed alert
                message_type = MALFORMED_MESSAGE_TYPE;
              }
            }
          break;
          case APPLICATION_CONTENT_TYPE:
            // for application messages we cannot determine whether they are encrypted or not
            message_type = UNKNOWN_MESSAGE_TYPE;
          break;
          case HEARTBEAT_CONTENT_TYPE:
            // a heartbeat message is at least 3 bytes long (1 byte type, 2 bytes payload length)
            // unfortunately, telling an encrypted message from an unencrypted message cannot be done reliably due to the variable length of padding
            // hence we just use unknown for either case
            if (record_length >= 3) {
              // unsigned char hb_msg_type = buf[byte_count+13];
              // u32 hb_length = read_bytes_to_uint32(buf, byte_count+14, 2);
              // unkown heartbeat message
              message_type = UNKNOWN_MESSAGE_TYPE;
            } else {
              // malformed heartbeat
              message_type = MALFORMED_MESSAGE_TYPE;
            }
          break;
          default:
            // unknown content and message type, should not be hit
            content_type = UNKNOWN_CONTENT_TYPE;
            message_type = UNKNOWN_MESSAGE_TYPE;
          break;
        }
      }

      status_code = (content_type << 8) + message_type;
      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = status_code;
      byte_count += record_length;
    } else {
      // we shouldn't really be reaching this code
      byte_count ++;
    }
  }

  *state_count_ref = state_count;
  return state_sequence;
}




unsigned int* extract_response_codes_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int num_to_read, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};
  char rtsp[5] = {0x52, 0x54, 0x53, 0x50, 0x2f};

  mem=(char *)ck_alloc(mem_size);
    state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) { 
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last two bytes are 0x0D0A
    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      if ((mem_count >= 5) && (memcmp(mem, rtsp, 5) == 0)) {
        //Extract the response code which is the first 3 bytes
        char temp[4];
        memcpy(temp, &mem[9], 4);
        temp[3] = 0x0;
        unsigned int message_code = (unsigned int) atoi(temp);

        if (message_code == 0) break;

        // HJ: not sure about this. Think through this carefully.
//        if (num_to_read < state_count) {
			state_count++;

			state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
			state_sequence[state_count - 1] = message_code;

//        }
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;   
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }


  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_ftp(unsigned char* buf, unsigned int buf_size, unsigned int num_to_read, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) { 
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      //Extract the response code which is the first 3 bytes
      char temp[4];
      memcpy(temp, mem, 4);
      temp[3] = 0x0;
      unsigned int message_code = (unsigned int) atoi(temp);

      if (message_code == 0) break;

//      if (num_to_read < state_count) {
		  state_count++;
		  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
		  state_sequence[state_count - 1] = message_code;
//      }
      mem_count = 0;
    } else {
      mem_count++;   
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }

  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}


unsigned int* extract_state_traversal_rtsp(region_t* regions, u32 region_count, Agraph_t *ipsm, unsigned int state_machine_state_cnt, unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
	unsigned int *response_codes = extract_response_codes_rtsp(buf, buf_size,
			region_count, state_count_ref);

	Agnode_t *n1;
	Agnode_t *n2;
	Agnode_t *first_node;
	Agedge_t *e;

	char *commands = (char*) ck_alloc(*state_count_ref);

	first_node = agnode(ipsm, "0", FALSE);
	char *current_state = agnameof(first_node);
	char *next_state = NULL;
	unsigned int i;

	unsigned int next_state_id = state_machine_state_cnt;

	unsigned int state_count = 1;
	unsigned int *state_sequence = NULL;

	state_sequence = (unsigned int*) ck_realloc(state_sequence,
			1 * sizeof(unsigned int));
	state_sequence[0] = 0;

	for (i = 0; i < *state_count_ref - 1; i++) { // state_count_ref -1 instead of state_count as the first response code is always "state 0"

		region_t region;
		region = regions[i];

		if (region_count < *state_count_ref - 1) { // *state_count_ref-1 since the first state is always 0
			break;
		}
		if (response_codes[i + 1] >= 400) {
			// in our version, we treat errors as no-traversal
			// this seems reasonable.

			state_count++;
			state_sequence = (unsigned int*) ck_realloc(state_sequence,
					state_count * sizeof(unsigned int));
			state_sequence[state_count - 1] = strtol(current_state, NULL, 10);

			continue;
		}
		char edge_label[15];
		edge_label[0] = '\0';

		for (int i = 0; region.command && region.command[i] && i < 14; i++) {
			edge_label[i] = tolower(region.command[i]);
			edge_label[i + 1] = NULL;
		}

		//get current node
		n1 = agnode(ipsm, current_state, FALSE);
		next_state = NULL;

		if (n1 != NULL) { // if null, it means we are at a newly created state, then always proceed to create a new state for any label here and we don't need to check for existing edges
			for (e = agfstedge(ipsm, n1); e; e = agnxtedge(ipsm, e, n1)) {
				n2 = aghead(e);

				char *label;
				label = agnameof(e);

				if (strcmp(label, edge_label) == 0) {
					// traverse along e
					next_state = agnameof(n2);
					break;

				}
			}
		}
		if (next_state == NULL && next_state_id < 50) { // cannot find existing edge, and we haven't passed the limit for # states in the state machine
			// create new edge and state
			// don't update here. Let afl-fuzz update_state_aware_variables handle updates to ipsm.
			char copied[5];

			sprintf(copied, "%d", next_state_id);
//			strcpy(next_state, &copied);
//			next_state = copied;

			next_state = ck_realloc(next_state,
					(strlen(copied) + 1) * sizeof(char));
			strcpy(next_state, &copied);
			next_state_id++;
		} else if (next_state == NULL) {
			next_state = current_state;
		}

		current_state = next_state;
		next_state = NULL;
		state_count++;
		state_sequence = (unsigned int*) ck_realloc(state_sequence,
				state_count * sizeof(unsigned int));
		state_sequence[state_count - 1] = strtol(current_state, NULL, 10);

	}

	ck_free(response_codes);

	*state_count_ref = state_count;
	return state_sequence;
}

unsigned int* extract_state_traversal_ftp(region_t* regions, u32 region_count, Agraph_t *ipsm, unsigned int state_machine_state_cnt, unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{

	unsigned int *response_codes = extract_response_codes_ftp(buf, buf_size,
			region_count, state_count_ref);

	Agnode_t *n1;
	Agnode_t *n2;
	Agnode_t *first_node;
	Agedge_t *e;

	char *commands = (char*) ck_alloc(*state_count_ref);

	first_node = agnode(ipsm, "0", FALSE);
	char *current_state = agnameof(first_node);
	char *next_state = NULL;
	unsigned int i;

	unsigned int next_state_id = state_machine_state_cnt;

	unsigned int state_count = 1;
	unsigned int *state_sequence = NULL;
	state_sequence = (unsigned int*) ck_realloc(state_sequence,
			1 * sizeof(unsigned int));
	state_sequence[0] = 0;

//	OKF("state cnt = %d", *state_count_ref);
//	  for (i = 0; i < *state_count_ref; i++) {
//	    OKF("state seq(i) = %d-",response_codes[i]);
//	  }

	if (*state_count_ref > 2) {
	for (i = 0; i < *state_count_ref - 2; i++) { // state_count_ref -1 instead of state_count as the first response code is always "state 0"
		region_t region;
		region = regions[i];

		if (i == region_count) { //
			break;
		}

//		OKF("\t i=%d, command=%s <> response code=%d <----", i, region.command, (response_codes[i+2]));

		// first state is 0, next state is that the server is ready, therefore use i+2 instead of i when getting response_codes
		if (response_codes[i + 2] >= 400 || (region.command == NULL || region.command[0] == '\0' || strlen(region.command) > 6)) {
			// in our version, we treat errors as no-traversal
			// this seems reasonable.
			// If the command is too long, its not likely to be a ftp command

			state_count++;
			state_sequence = (unsigned int*) ck_realloc(state_sequence,
					state_count * sizeof(unsigned int));
			state_sequence[state_count - 1] = strtol(current_state, NULL, 10);

			continue;
		}
		char edge_label[15];
		edge_label[0] = '\0';

		for (int i = 0; region.command && region.command[i] && i < 14; i++) {
//			edge_label[i] = tolower(region.command[i]);
			edge_label[i] = region.command[i];
			edge_label[i + 1] = NULL;
		}

		Agnode_t *n;
		// get next node if exists
		for (n = agfstnode(ipsm); n; n = agnxtnode(ipsm,n)) {
			char* node_label;
			node_label = agget(n, "label");

//			OKF("within state traversal extraction: node_label=%s,  edge_label=%s, strcmp =%d", node_label, edge_label, strcmp(node_label, edge_label));

			if (node_label && strcmp(node_label, edge_label) == 0) {
				next_state = agnameof(n);
				break;
			}
//			OKF("getting next node");
		}


		// unable to get next node, create a new node
		if (next_state == NULL && next_state_id < 30) { // cannot find existing edge, and we haven't passed the limit for # states in the state machine

			// create new edge and state
			// don't update ipsm here. Let afl-fuzz's update_state_aware_variables handle updates to ipsm.

			char copied[5];

			sprintf(copied, "%d", next_state_id);

			next_state = ck_realloc(next_state,
					(strlen(copied) + 1) * sizeof(char));
			strcpy(next_state, &copied);
			next_state_id++;

		} else if (next_state == NULL) {
			// just repeat the current state
			next_state = current_state;
		}

		current_state = next_state;
		next_state = NULL;
		state_count++;
		state_sequence = (unsigned int*) ck_realloc(state_sequence,
				state_count * sizeof(unsigned int));
		state_sequence[state_count - 1] = strtol(current_state, NULL, 10);

	}
	}

	*state_count_ref = state_count;
	return state_sequence;
}
// kl_messages manipulating functions

klist_t(lms) *construct_kl_messages(u8* fname, region_t *regions, u32 region_count) 
{
  FILE *fseed = NULL;
  fseed = fopen(fname, "rb"); 
  if (fseed == NULL) PFATAL("Cannot open seed file %s", fname);
  
  klist_t(lms) *kl_messages = kl_init(lms);
  u32 i;

  for (i = 0; i < region_count; i++) {
    //Identify region size
    u32 len = regions[i].end_byte - regions[i].start_byte + 1;

    //Create a new message
    message_t *m = (message_t *) ck_alloc(sizeof(message_t));
    m->mdata = (char *) ck_alloc(len);
    m->msize = len;  
    if (m->mdata == NULL) PFATAL("Unable to allocate memory region to store new message");          
    fread(m->mdata, 1, len, fseed);

    //Insert the message to the linked list
    *kl_pushp(lms, kl_messages) = m;
  }

  if (fseed != NULL) fclose(fseed);
  return kl_messages;
}

void delete_kl_messages(klist_t(lms) *kl_messages) 
{ 
  /* Free all messages in the list before destroying the list itself */
  message_t *m;
  
  int ret = kl_shift(lms, kl_messages, &m);
  while (ret == 0) {
    if (m) {
      ck_free(m->mdata);
      ck_free(m);
    }
    ret = kl_shift(lms, kl_messages, &m);
  }
  
  /* Finally, destroy the list */
	kl_destroy(lms, kl_messages);
}

kliter_t(lms) *get_last_message(klist_t(lms) *kl_messages) 
{
  kliter_t(lms) *it;
  it = kl_begin(kl_messages);
  while (kl_next(it) != kl_end(kl_messages)) {
    it = kl_next(it);
  }
  return it;
}


u32 save_kl_messages_to_file(klist_t(lms) *kl_messages, u8 *fname, u8 replay_enabled, u32 max_count) 
{
  u8 *mem = NULL;
  u32 len = 0, message_size = 0;
  kliter_t(lms) *it;

  s32 fd = open(fname, O_WRONLY | O_CREAT, 0600);
  if (fd < 0) PFATAL("Unable to create file '%s'", fname);

  u32 message_count = 0;
  //Iterate through all messages in the linked list
  for (it = kl_begin(kl_messages); it != kl_end(kl_messages) && message_count < max_count; it = kl_next(it)) {
    message_size = kl_val(it)->msize;
    if (replay_enabled) {
		  mem = (u8 *)ck_realloc(mem, 4 + len + message_size);

      //Save packet size first
      u32 *psize = (u32*)&mem[len];
      *psize = message_size;

      //Save packet content 
      memcpy(&mem[len + 4], kl_val(it)->mdata, message_size);
      len = 4 + len + message_size;
    } else {
      mem = (u8 *)ck_realloc(mem, len + message_size);

      //Save packet content 
      memcpy(&mem[len], kl_val(it)->mdata, message_size);
      len = len + message_size;
    }
    message_count++;
  }  

  //Write everything to file & close the file
  ck_write(fd, mem, len, fname);
  close(fd);

  //Free the temporary buffer
  ck_free(mem);

  return len;
}

region_t* convert_kl_messages_to_regions(klist_t(lms) *kl_messages, u32* region_count_ref, u32 max_count) 
{
  region_t *regions = NULL;
  kliter_t(lms) *it;

  unsigned int first_token_size;

  u32 region_count = 1;
  s32 cur_start = 0, cur_end = 0;
  //Iterate through all messages in the linked list
  for (it = kl_begin(kl_messages); it != kl_end(kl_messages) && region_count <= max_count ; it = kl_next(it)) {
    regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));

    cur_end = cur_start + kl_val(it)->msize - 1;
    if (cur_end < 0) PFATAL("End_byte cannot be negative");

    regions[region_count - 1].start_byte = cur_start;
    regions[region_count - 1].end_byte = cur_end;
    regions[region_count - 1].state_sequence = NULL;
    regions[region_count - 1].state_count = 0;
    
    // take the first token (the first word delimited by a space) in the region

	 if (kl_val(it)->msize > 0) {
		 first_token_size = index_of(kl_val(it)->mdata, kl_val(it)->msize, " ");

		 if (first_token_size < 0 || first_token_size >= (cur_end - cur_start) || first_token_size > 15) {
			 first_token_size = 0; // just allocate enough space for the null terminator
		 }
		 regions[region_count - 1].command = (char *)ck_alloc(first_token_size + 1);
		 memcpy(regions[region_count - 1].command, kl_val(it)->mdata, first_token_size);
		 regions[region_count - 1].command[first_token_size] = NULL;
	 } else {
		 regions[region_count - 1].command = NULL;
	 }

    cur_start = cur_end + 1;
    region_count++;
  }  
  
  *region_count_ref = region_count - 1; 
  return regions;
}

// Network communication functions

int net_send(int sockfd, struct timeval timeout, char *mem, unsigned int len) {
  unsigned int byte_count = 0;
  int n;
  struct pollfd pfd[1]; 
  pfd[0].fd = sockfd;
  pfd[0].events = POLLOUT;
  int rv = poll(pfd, 1, 1);  

  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
  if (rv > 0) {
    if (pfd[0].revents & POLLOUT) {
      while (byte_count < len) {
        usleep(10);
        n = send(sockfd, &mem[byte_count], len - byte_count, MSG_NOSIGNAL);
        if (n == 0) return byte_count;
        if (n == -1) return -1;
        byte_count += n;
      }
    }
  }
  return byte_count;
}

int net_recv(int sockfd, struct timeval timeout, int poll_w, char **response_buf, unsigned int *len) {
  char temp_buf[1000];
  int n;
  struct pollfd pfd[1]; 
  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;
  int rv = poll(pfd, 1, poll_w);
  
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
  // data received
  if (rv > 0) {
    if (pfd[0].revents & POLLIN) {
      n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);
      if ((n < 0) && (errno != EAGAIN)) {
        return 1;
      }
      while (n > 0) {
        usleep(10);
        *response_buf = (unsigned char *)ck_realloc(*response_buf, *len + n);
        memcpy(&(*response_buf)[*len], temp_buf, n);
        *len = *len + n;
        n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);
        if ((n < 0) && (errno != EAGAIN)) {
          return 1;
        }
      }   
    }
  } else 
    if (rv < 0) // an error was returned 
      return 1;
 
  // rv == 0 poll timeout or all data pending after poll has been received successfully
  return 0;
}

// Utility function

void save_regions_to_file(region_t *regions, unsigned int region_count, unsigned char *fname)
{
  int fd;
  FILE* fp;

  fd = open(fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
  
  if (fd < 0) return;

  fp = fdopen(fd, "w");

  if (!fp) {
    close(fd);
    return;
  }

  int i;
  
  for(i=0; i < region_count; i++) {
     fprintf(fp, "Region %d - Start: %d, End: %d, Command %s\n", i, regions[i].start_byte, regions[i].end_byte, regions[i].command ? regions[i].command : "None");
  }

  fclose(fp);
}

int str_split(char* a_str, const char* a_delim, char **result, int a_count)
{
	char *token;
	int count = 0;

	/* count number of tokens */
	/* get the first token */
	char* tmp1 = strdup(a_str);
	token = strtok(tmp1, a_delim);

	/* walk through other tokens */
	while (token != NULL)
	{
		count++;
		token = strtok(NULL, a_delim);
	}

	if (count != a_count)
	{
		return 1;
	}

	/* split input string, store tokens into result */
	count = 0;
	/* get the first token */
	token = strtok(a_str, a_delim);

	/* walk through other tokens */

	while (token != NULL)
	{
		result[count] = token;
		count++;
		token = strtok(NULL, a_delim);
	}

	free(tmp1);
	return 0;
}

void str_rtrim(char* a_str)
{
	char* ptr = a_str;
	int count = 0;
	while ((*ptr != '\n') && (*ptr != '\t') && (*ptr != ' ') && (count < strlen(a_str))) {
		ptr++;
		count++;
	}
	if (count < strlen(a_str)) {
		*ptr = '\0';
	}
}

int parse_net_config(u8* net_config, u8* protocol, u8** ip_address, u32* port) 
{
  char  buf[80];
  char **tokens;
  int tokenCount = 3;

  tokens = (char**)malloc(sizeof(char*) * (tokenCount));

  if (strlen(net_config) > 80) return 1;

  strncpy(buf, net_config, strlen(net_config));
   str_rtrim(buf);
      
  if (!str_split(buf, "/", tokens, tokenCount))
  {
      if (!strcmp(tokens[0], "tcp:")) {
        *protocol = PRO_TCP;
      } else if (!strcmp(tokens[0], "udp:")) {
        *protocol = PRO_UDP;
      } else return 1;

      //TODO: check the format of this IP address
      *ip_address = strdup(tokens[1]);

      *port = atoi(tokens[2]);
      if (*port == 0) return 1;
  }
  return 0;
}

u8* state_sequence_to_string(unsigned int *stateSequence, unsigned int stateCount) {
  u32 i = 0;
 
  u8 *out = NULL;
  
  char strState[10];
  int len = 0;
  for (i = 0; i < stateCount; i++) {
    //Limit the loop to shorten the output string
    if ((i >= 2) && (stateSequence[i] == stateSequence[i - 1]) && (stateSequence[i] == stateSequence[i - 2])) continue;
    unsigned int stateID = stateSequence[i];
    if (i == stateCount - 1) {
      sprintf(strState, "%d", (int) stateID);
    } else {
      sprintf(strState, "%d-", (int) stateID);
    }
    out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
    memcpy(&out[len], strState, strlen(strState) + 1);
    len=strlen(out);
    //As Linux limit the size of the file name
    //we set a fixed upper bound here
    if (len > 150 && (i + 1 < stateCount)) {
      sprintf(strState, "%s", "end-at-");
      out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
      memcpy(&out[len], strState, strlen(strState) + 1);
      len=strlen(out);

      sprintf(strState, "%d", (int) stateSequence[stateCount - 1]);
      out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
      memcpy(&out[len], strState, strlen(strState) + 1);
      len=strlen(out);
      break;
    }
  }
  return out;
}

u8* command_sequence_to_string(region_t* regions, u32 region_count) {
  u32 i = 0;

  u8 *out = NULL;

  char strState[15];
  int len = 0;
  for (i = 0; i < region_count; i++) {
    //Limit the loop to shorten the output string
	 char* command = regions[i].command;
    if (i == region_count - 1) {
      sprintf(strState, "%s", command);
    } else {
      sprintf(strState, "%s-", command);
    }
    out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
    memcpy(&out[len], strState, strlen(strState) + 1);
    len=strlen(out);
  }
  return out;
}



void hexdump(unsigned char *msg, unsigned char * buf, int start, int end) {
  printf("%s : ", msg);
  for (int i=start; i<=end; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}


u32 read_bytes_to_uint32(unsigned char* buf, unsigned int offset, int num_bytes) {
  u32 val = 0;
  for (int i=0; i<num_bytes; i++) {
    val = (val << 8) + buf[i+offset];
  }
  return val;
}



unsigned int index_of(char *buf, int buf_size, char *exclude) {
  char *c;

  unsigned int i;
  for (i = 0; i < 16 && i < buf_size; i++ ) {
      for (c = exclude; *c; c++) {
    	  if (buf[i] == *c)
    		  break;
      }
      if (*c) break;
   }

  return i;
}

